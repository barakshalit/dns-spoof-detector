import subprocess
import re
from datetime import datetime
import signal
import sys
import os
import requests

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

    def get_nslookup_address(self, domain):
        try:
            # Run the nslookup command for the specified domain
            result = subprocess.run(['nslookup', domain], capture_output=True, text=True)
            
            # Check if the command succeeded
            if result.returncode != 0:
                print(f"nslookup failed with error: {result.stderr}")
                return None

            # Extract the actual resolved IP address (skip resolver address)
            address = None
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith('Address:') and '#' not in line:  # Exclude lines with '#'
                    address = line.split(':')[-1].strip()  # Get the part after 'Address:'
                    break

            return address
        except Exception as e:
            print(f"Error running nslookup: {e}")
            return None

    def parse_dns_query(self, line):
        try:
            # Extract domain from DNS query
            domain_match = re.search(r"\b[\w.-]+\.(?:com|co\.il|org)\b", line)
            domain = domain_match.group(0) if domain_match else None
            print("DEBUG: ", domain)
            # Extract IP address from DNS response
            ip = self.get_nslookup_address(domain)

            if not domain:
                domain = "Unknown domain"
            if not ip:
                ip = "Unknown IP"
            # Return the parsed domain and IP
            return domain , ip

        except Exception as e:
            print(f"Error parsing line: {e}")
            print("-" * 50)
            return None , None

    def parse_response(self, response, api):
        if response.status_code == 200:
            # Parse the response to JSON
            try:
                data = response.json()
                if api == "google":
                    ip_from_API = data["Answer"]
                    for answer in ip_from_API:
                        ip_from_API = answer["data"]
                elif api == "network_calc":
                    ip_from_API = data["records"]["A"][0]["address"]
                elif api == "whois":
                    ip_from_API = data["dnsRecords"][0]["address"]

                # Search for a specific field
                
                if ip_from_API:
                    return ip_from_API
                else:
                    print("Field not found in the response.")
            except ValueError as e:
                print("Failed to parse JSON:", e)

        else:
            print(f"Request failed with status code {response.status_code}")

    def validate_ip(self,domain, ip_from_nslookup):
        try:
            whois_API_key="10733bc54c464990a4d777fd6687c66e"
            IPapi_API_key = "36371fec54d5432c212a36cdb74bb65d"
            dns_google_IP = "8.8.8.8" # dns.google
            whois_IP = "172.233.38.212" #api.whoisfreaks.com
            network_calc_IP = "134.209.130.15" #networkcalc.com
            # answers from apis
            answers = []
            google_dns = requests.get(f"https://{dns_google_IP}/resolve?name={domain}")
            who_is = requests.get(f"https://{whois_IP}/v2.0/dns/live?apiKey={whois_API_key}&domainName={domain}&type=all",verify=False)
            network_calc = requests.get(f"https://{network_calc_IP}/api/dns/lookup/{domain}",verify=False)
            answers.append(self.parse_response(google_dns, "google"))
            answers.append(self.parse_response(network_calc, "network_calc"))
            answers.append(self.parse_response(who_is, "whois"))

        except Exception as e:
            print(f"Error parsing line: {e}")
            print("-" * 50)
            return None , None
            
        return answers

   
    def start_monitoring(self):
        try:
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
                bufsize=1,  # Line-buffered
            )
        
            print(f"Starting DNS monitoring on interface {self.interface}...")
            print("Press Ctrl+C to stop monitoring\n")

            while True:
                line = self.process.stdout.readline()
                if not line:
                    break

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log = f"{timestamp} - Raw line from tcpdump: {line}\n"
                domain, ip = self.parse_dns_query(line)  
                log = log + f"Found domain: {domain}\n"    
                log = log + f"Found IP: {ip}\n"   
                self.validate_ip(domain, ip)
                print(log) 
                print("-" * 50)

                #Log to file
                with open("dns_queries.log", "a") as f:
                    f.write(f"{log}\n")

        except Exception as e:
            print(f"Error: {e}")
        finally:
            if self.process:
                self.process.terminate()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root privileges to run tcpdump.")
        print("Please run with sudo: sudo python3 dns_monitor.py")
        sys.exit(1)

    monitor = DNSMonitor()
    monitor.start_monitoring()
