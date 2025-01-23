import subprocess
import re
from datetime import datetime
import signal
import sys
import os
import requests
import threading
import queue
import urllib3
import time
import argparse
import webbrowser
import time
import socket

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DNSSpoofDetector:

    def __init__(self, verbose_logs_input=False, interface="eth0"):
        self.interface = interface
        self.process = None
        self.queue = queue.Queue()
        self.filtered_queue = queue.Queue()
        self.log_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.verbose_logs = verbose_logs_input
        self.info_site_html_path = "/usr/local/bin/alert.html"
        self.trusted_domains = {}
        signal.signal(signal.SIGINT, self.signal_handler)


    def signal_handler(self, signum, frame):
        print("\nStopping DNS monitoring...")
        if self.process:
            self.process.terminate()
        sys.exit(0)


    # Perform nslookup for the specified domain for ip adress from local DNS resolver
    def get_nslookup_address(self, domain):
        try:
            return socket.gethostbyname(domain)
        except Exception as e:
            print(f"Socket resolution error: {e}")
            return None


    # Open the HTML file in the default browser
    def open_html_file(self, malicious_domain):
        # Check if the file exists
        if os.path.exists(self.info_site_html_path):
            # Read the HTML file and update it
            with open(self.info_site_html_path, "r") as file:
                html_content = file.read()

            updated_html = html_content.replace("{domain}", malicious_domain)

            # Save the updated HTML to a new file (or overwrite the original)
            temp_html_path = os.path.join(os.path.dirname(self.info_site_html_path), "updated_site.html")
            with open(temp_html_path, "w") as file:
                file.write(updated_html)

            # Open the updated HTML file in the default browser
            webbrowser.open(f'file://{os.path.abspath(temp_html_path)}')
            print(f"Opening {temp_html_path} in the default browser...")
        else:
            print(f"Error: {self.info_site_html_path} does not exist.")


    # Parse the DNS query from the tcpdump line for domain name and ip address
    def parse_dns_query(self, line):
        try:
            # Extract domain from DNS query
            domain_match = re.search(r"\b[\w.-]+\.(?:com|co\.il|org|net)\b", line)
            domain = domain_match.group(0) if domain_match else None

            # Extract IP address from DNS response
            ip = False
            if domain:
                ip = self.get_nslookup_address(domain)

            if not domain:
                domain = False
            if not ip:
                ip = False
            # Return the parsed domain and IP
            return domain , ip

        except Exception as e:
            print(f"Error parsing line: {e}")
            print("-" * 50)
            return None , None


    # Parse the response from the API
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
                elif api == "IP_API":
                    ip_from_API = data["query"]
                
                if ip_from_API:
                    return ip_from_API
                else:
                    print("Failed to find ip from the response.")
            except ValueError as e:
                print("Failed to parse JSON:", e)

        else:
            print(f"Request failed with status code {response.status_code}")


    # Validate the IP address from the DNS query against multiple APIs
    def validate_ip(self, domain, ip_from_nslookup):
        try:
            if domain in self.trusted_domains and ip_from_nslookup == self.trusted_domains[domain]: # checking cache for trusted domains
                return "VALID (cached)"
            
            dns_google_IP = "8.8.8.8" # dns.google
            network_calc_IP = "134.209.130.15" #networkcalc.com
            IP_API_IP = "208.95.112.1" #ip-api.com

            # Setting up the request urls for the APIs
            available_request_url=[]
            api_order_list = ["google", "network_calc", "IP_API"]
            google_dns_request_url = f"https://{dns_google_IP}/resolve?name={domain}"
            network_calc_request_url = f"https://{network_calc_IP}/api/dns/lookup/{domain}"
            IP_API_request_url = f"http://{IP_API_IP}/json/{domain}"
            available_request_url.append(google_dns_request_url)
            available_request_url.append(network_calc_request_url)
            available_request_url.append(IP_API_request_url)

            valid, ip_from_ip_api_list = self.validate_against_apis(available_request_url, api_order_list, ip_from_nslookup, retries=3)

            if valid:
                self.trusted_domains[domain] = ip_from_nslookup
                return "VALID"

            # ip isn't valid - check if the ip comes from cdn
            isp_from_nslookup =  self.make_request_with_retries(f"http://{IP_API_IP}/json/{ip_from_nslookup}").json()["isp"]

            google_api_respone_ip = ip_from_ip_api_list[0]
            isp_from_google = self.make_request_with_retries(f"http://{IP_API_IP}/json/{google_api_respone_ip}").json()["isp"]

            if isp_from_nslookup == isp_from_google:
                self.trusted_domains[domain] = ip_from_nslookup
                return "VALID (isp match)"

            network_calc_response_ip = ip_from_ip_api_list[1]
            isp_from_network_calc = self.make_request_with_retries(f"http://{IP_API_IP}/json/{network_calc_response_ip}").json()["isp"]
            if isp_from_nslookup == isp_from_network_calc:
                self.trusted_domains[domain] = ip_from_nslookup
                return "VALID (isp match)"

 
            IP_API_response_ip = ip_from_ip_api_list[2]
            isp_from_ip_api = self.make_request_with_retries(f"http://{IP_API_IP}/json/{IP_API_response_ip}").json()["isp"]
            if isp_from_nslookup == isp_from_ip_api:
                self.trusted_domains[domain] = ip_from_nslookup
                return "VALID (isp match)"
          

        except Exception as e:
            return f"Error validating with exception: {e}"

        self.open_html_file(domain)
        return "INVALID"


    # Validate the IP address from the DNS query against multiple APIs, performing cyclic retries to enhance performance
    def validate_against_apis(self, available_request_url, api_order_list, ip_from_nslookup, retries=3):
        retries_for_apis = [0,0,0]
        request_sent = [False, False, False]
        url_index = 0
        ip_from_api_list = [None] * 3
        # not all url request was fullfiled
        while False in request_sent:
            if not request_sent[url_index]: # current API still didn't send request
                if retries_for_apis[url_index] <= retries: # we haven't used all retries for current API
                    retries_for_apis[url_index] += 1
                    response = requests.get(available_request_url[url_index], verify=False)
                    if response.status_code == 200:
                        ip_from_api = self.parse_response(response, api_order_list[url_index])
                        ip_from_api_list[url_index] = ip_from_api
                        if ip_from_nslookup == ip_from_api:
                            return True , None
                        else:
                            request_sent[url_index] = True
                    elif response.status_code != 429:                 
                        raise Exception(f"Error code {response.status_code} from request {available_request_url[url_index]}")
                
            url_index = (url_index + 1) % len(available_request_url) # iterating over next request url
        
        return False, ip_from_api_list


    # Make a request with retries
    def make_request_with_retries(self, url, retries=4):
            for i in range(retries):
                response = requests.get(url, verify=False)
                if response.status_code == 200:
                    return response
                else:                 # Too many requests
                    time.sleep(1)
            raise Exception("Failed to fetch data after retries.")


    # Process lines from tcpdump
    def process_lines(self):
        while not self.stop_event.is_set():
            try:
                line = self.queue.get(timeout=0.3)
                if line:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    # Parse the DNS query from the tcpdump line for domain name and ip address
                    domain, ip = self.parse_dns_query(line)
                    if (not domain or not ip) and not self.verbose_logs:
                        continue
                    
                    log = ("-" * 50) + "\n"
                    log += f"{timestamp}\n"
                    log += f"Raw line from tcpdump: {line.strip()}\n"
                    log += f"Found domain: {domain}\n"
                    log += f"Found IP: {ip}\n"
                    log += f"Validation from API: {self.validate_ip(domain, ip)}\n"

                    if self.verbose_logs:
                        print(log)
                    self.log_queue.put(log)
                    self.filtered_queue.put(log)
            except queue.Empty:
                continue

    def write_log_to_file(self):
        log_batch = []
        while not self.stop_event.is_set():
            try:
                log = self.log_queue.get(timeout=3)
                log_batch.append(log)

                if len(log_batch) >= 20:  # Write in batches of 10
                    with open("/root/Desktop/dns_queries.log", "a") as f:
                        f.writelines(log_batch)
                    log_batch = []
            except queue.Empty:
                continue
    
    # Start monitoring DNS queries
    def start_monitoring(self):
        try:
            # Run tcpdump command to capture DNS queries
            cmd = f"tcpdump -i {self.interface} -n -l -vv 'udp port 53'"
            print(f"Running command: {cmd}")

            if os.geteuid() != 0:
                cmd = f"sudo {cmd}"

            self.process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1,
            )

            # start a new thread to process lines from tcpdump
            threading.Thread(target=self.process_lines, daemon=True).start()
            # start a new thread to write logs to file
            threading.Thread(target=self.write_log_to_file, daemon=True).start()

            print(f"Starting DNS monitoring on interface {self.interface}... with verbose logs: {self.verbose_logs}")
            print("Press Ctrl+C to stop monitoring\n")

            # main thread putting lines from tcpdump in queue
            while not self.stop_event.is_set():
                line = self.process.stdout.readline()
                if not line:
                    break
                self.queue.put(line)

        except Exception as e:
            print(f"Error: {e}")
        finally:
            if self.process:
                self.process.terminate()
                
def stop_monitoring(self):
    self.stop_event.set()  # Signal all threads to stop
    if self.process:
        self.process.terminate()  # Terminate the subprocess
    print("Monitoring stopped.")

def get_logs(self):
        """Retrieve logs from the queue."""
        try:
            return self.queue.get_nowait()  # Try to get a log without blocking
        except queue.Empty:
            return None  # Return None if no logs are available

def main(verbose_logs_input):
    # Check if the script is running as root
    if os.geteuid() != 0:
        print("This script requires root privileges to run tcpdump.")
        print("Please run with sudo: sudo python3 dns_monitor.py")
        sys.exit(1)

    detector = DNSSpoofDetector(verbose_logs_input)
    detector.start_monitoring()


# Entry point of the project
if __name__ == "__main__":

    # Set up argument parser
    parser = argparse.ArgumentParser(description="DNS Monitoring Script")

    # Add arguments
    parser.add_argument('--verbose', action='store_true', help="Increase log verbosity")

    # Parse the arguments
    args = parser.parse_args()

    # Call main with parsed arguments
    main(args.verbose)

