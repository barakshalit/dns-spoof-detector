import subprocess
import re
from datetime import datetime
import signal
import sys
import os

class DNSMonitor:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.process = None
        signal.signal(signal.SIGINT, self.signal_handler)
        
    def signal_handler(self, signum, frame):
        print("\nStopping DNS monitoring...")
        if self.process:
            self.process.terminate()
        sys.exit(0)
        
    def get_ip_from_nslookup(self, url):
        try:
            # Run nslookup against the local dnsmasq server (127.0.0.1)
            result = subprocess.run(['nslookup', url, '127.0.0.1'], capture_output=True, text=True)
            
            # Parse the output of nslookup to extract the IP address under the 'Name' section
            ip_address = None
            in_address_section = False  # Flag to start capturing 'Name' section
            for line in result.stdout.splitlines():
                if "Name:" in line:
                    in_address_section = True  # Start capturing addresses
                if in_address_section and "Address:" in line:
                    ip_address = line.split(':')[-1].strip()  # Extract IP address
                    break  # Exit after the first found address
            
            return ip_address
            
        except Exception as e:
            print(f"Error during nslookup: {e}")
            return None

    def parse_dns_query(self, line):
        try:
            # Print raw line for debugging
            print(f"Raw line: {line}")
            
            # More comprehensive regex patterns to match different DNS query types
            query_patterns = [
                r'\d+\+\s*(\w+)\?\s*([a-zA-Z0-9.-]+)\s*\(',  # Match Type65 and other types, and the domain
                r'A\? ([\w.-]+)',  # Standard A record query
                r'AAAA\? ([\w.-]+)',  # IPv6 query
                r' ([a-zA-Z0-9.-]+)\. A\? ',  # Alternative A record format
                r'([a-zA-Z0-9.-]+) IN A'  # Another common format
            ]
            
            ip_patterns = [
                r'A ([\d.]+)',  # IPv4 response
                r'AAAA ([0-9a-f:]+)',  # IPv6 response
                r' ([\d.]+) A '  # Alternative IPv4 format
            ]
            
            domain = None
            # Try different query patterns to find the domain
            for pattern in query_patterns:
                match = re.search(pattern, line)
                if match:
                    domain = match.group(2)  # The second group should be the domain
                    print(f"Found domain: {domain}")
                    break
            
            # If no domain is found, return early to avoid further errors
            if not domain:
                print("No valid domain found in the query.")
                return None, None
            
            ip = None
            # Try different IP patterns
            for pattern in ip_patterns:
                match = re.search(pattern, line)
                if match:
                    ip = match.group(1)
                    print(f"Found IP: {ip}")
                    break
            
            # Return the domain and IP
            return domain, ip
        
        except Exception as e:
            print(f"Error parsing line: {e}")
        return None, None

    def start_monitoring(self):
        try:
            # Modified tcpdump command for more verbose output
            cmd = f"tcpdump -i {self.interface} -n -l -vv 'udp port 53'"
            print(f"Running command: {cmd}")
            
            # Start tcpdump with sudo if not root
            if os.geteuid() != 0:
                cmd = f"sudo {cmd}"
            
            self.process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1  # Line buffered
            )
            
            # Check for tcpdump errors
            stderr_line = self.process.stderr.readline()
            if stderr_line:
                print(f"tcpdump stderr: {stderr_line}")
            
            print(f"Starting DNS monitoring on interface {self.interface}...")
            print("Press Ctrl+C to stop monitoring\n")
            
            while True:
                line = self.process.stdout.readline()
                if not line:
                    break
                    
                domain = self.parse_dns_query(line)
                if domain:
                    # Only print the requested URL and its resolved IP
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    print(f"\nRequested URL: {domain}")
                    
                    # Get IP from nslookup
                    ip_address = self.get_ip_from_nslookup(domain)
                    if ip_address:
                        print(f"IP from nslookup: {ip_address}")
                    else:
                        print(f"IP not found for {domain}")
                    
                    print("-" * 50)
                    
                    # Log to file
                    with open("dns_queries.log", "a") as f:
                        f.write(f"[{timestamp}] {domain} -> {ip_address if ip_address else 'No IP'}\n")
                    
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if self.process:
                self.process.terminate()

if __name__ == "__main__":
    # Check if running as root
    if os.geteuid() != 0:
        print("This script requires root privileges to run tcpdump.")
        print("Please run with sudo: sudo python3 dns_monitor.py")
        sys.exit(1)
        
    monitor = DNSMonitor()
    monitor.start_monitoring()
