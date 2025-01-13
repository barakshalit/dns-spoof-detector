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
from time import sleep
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DNSMonitor:

    def __init__(self, verbose_logs_input=False, interface="eth0"):
        self.interface = interface
        self.process = None
        self.queue = queue.Queue()
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


    def get_nslookup_address(self, domain):
        try:
            if domain:
                # Run the nslookup command for the specified domain
                result = subprocess.run(['nslookup', domain], capture_output=True, text=True)
                
                # Check if the command succeeded
                if result.returncode != 0:
                    if (self.verbose_logs):
                        print(f"nslookup failed with error: {result.stderr} for domain {domain}")
                    return None

                # Extract the actual resolved IP address (skip resolver address)
                address = None
                for line in result.stdout.splitlines():
                    try:
                        line = line.strip()
                        if line.startswith('Address:') and '#' not in line:  # Exclude lines with '#'
                            address = line.split(':')[-1].strip()  # Get the part after 'Address:'
                            break
                    except Exception as e:
                        print(f"Could not parse adderss from nslookup, in line: {line} for domain {domain}")
                        return None

                return address
        except Exception as e:
            print(f"Error running nslookup: {e}")
            return None

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


    def parse_dns_query(self, line):
        try:
            # Extract domain from DNS query
            domain_match = re.search(r"\b[\w.-]+\.(?:com|co\.il|org)\b", line)
            domain = domain_match.group(0) if domain_match else None

            # Extract IP address from DNS response
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

    def validate_ip(self, domain, ip_from_nslookup):
        try:
            if domain in self.trusted_domains and ip_from_nslookup == self.trusted_domains[domain]: # checking cache for trusted domains
                return "VALID (cached)"
            
            dns_google_IP = "8.8.8.8" # dns.google
            network_calc_IP = "134.209.130.15" #networkcalc.com
            IP_API_IP = "208.95.112.1" #ip-api.com

            # google dns api validation
            available_request_url=[]
            api_order_list = ["google", "network_calc", "IP_API"]
            google_dns_request_url = f"https://{dns_google_IP}/resolve?name={domain}"
            network_calc_request_url = f"https://{network_calc_IP}/api/dns/lookup/{domain}"
            IP_API_request_url = f"http://{IP_API_IP}/json/{domain}"
            available_request_url.append(google_dns_request_url)
            available_request_url.append(network_calc_request_url)
            available_request_url.append(IP_API_request_url)

            valid = self.validate_against_apis(available_request_url, api_order_list, ip_from_nslookup, retries=3)

            if valid:
                self.trusted_domains[domain] = ip_from_nslookup
                return "VALID"

            # ip isn't valid - check if the ip comes from cdn
            isp_from_nslookup =  self.make_request_with_retries(f"http://{IP_API_IP}/json/{ip_from_nslookup}").json()["isp"]

            google_dns_request_url = f"https://{dns_google_IP}/resolve?name={domain}"
            google_dns_response = self.make_request_with_retries(google_dns_request_url)
            google_api_respone_ip = self.parse_response(google_dns_response, "google")
            isp_from_google = self.make_request_with_retries(f"http://{IP_API_IP}/json/{google_api_respone_ip}").json()["isp"]

            if isp_from_nslookup == isp_from_google:
                self.trusted_domains[domain] = ip_from_nslookup
                return "VALID (isp match)"
            
            network_calc_request_url = f"https://{network_calc_IP}/api/dns/lookup/{domain}"
            network_calc_response = self.make_request_with_retries(network_calc_request_url)
            network_calc_response_ip = self.parse_response(network_calc_response, "network_calc")
            isp_from_network_calc = self.make_request_with_retries(f"http://{IP_API_IP}/json/{network_calc_response_ip}").json()["isp"]
            if isp_from_nslookup == isp_from_network_calc:
                self.trusted_domains[domain] = ip_from_nslookup
                return "VALID (isp match)"

            IP_API_request_url = f"http://{IP_API_IP}/json/{domain}"
            IP_API_response = self.make_request_with_retries(IP_API_request_url)
            IP_API_response_ip = self.parse_response(IP_API_response, "IP_API")

            isp_from_ip_api = self.make_request_with_retries(f"http://{IP_API_IP}/json/{IP_API_response_ip}").json()["isp"]
            if isp_from_nslookup == isp_from_ip_api:
                self.trusted_domains[domain] = ip_from_nslookup
                return "VALID (isp match)"
          

        except Exception as e:
            return f"Error validating with exception: {e}"

        self.open_html_file(domain)
        return "INVALID"




    def validate_against_apis(self, available_request_url, api_order_list, ip_from_nslookup, retries=3) -> bool:
        retries_for_apis = [0,0,0]
        request_sent = [False, False, False]
        url_index = 0
        ip_from_apis = []
        # not all url request was fullfiled
        while False in request_sent:
            if not request_sent[url_index]: # there are still awaiting requests
                if retries_for_apis[url_index] <= retries: # we haven't used all retries
                    wait_time = 2 ** retries_for_apis[url_index]  # Exponential backoff
                    retries_for_apis[url_index] += 1
                    time.sleep(1)
                    response = requests.get(available_request_url[url_index], verify=False)
                    if response.status_code == 200:
                        ip_from_api = self.parse_response(response, api_order_list[url_index])
                        ip_from_apis.append(ip_from_api)
                        if ip_from_nslookup == ip_from_api:
                            return True, ip_from_apis
                        else:
                            request_sent[url_index] = True
                    elif response.status_code != 429:                 
                        raise Exception(f"Error code {response.status_code} from request {available_request_url[url_index]}")

                else:
                    raise Exception("Failed to fetch data after retries.")
                
            url_index = (url_index + 1) % len(available_request_url) # iterating over next request url
        
        return False

    def make_request_with_retries(self, url, retries=4):
            for i in range(retries):
                response = requests.get(url, verify=False)
                if response.status_code == 200:
                    return response
                else:                 # Too many requests
                    wait_time = 2 ** i  # Exponential backoff
                    time.sleep(1)
            raise Exception("Failed to fetch data after retries.")

    def process_lines(self):
        while not self.stop_event.is_set():
            try:
                line = self.queue.get(timeout=0.5)
                if line:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    domain, ip = self.parse_dns_query(line)
                    if (not domain or not ip) and not self.verbose_logs:
                        continue
                    
                    log = ("-" * 50) + "\n"
                    log += f"{timestamp}\n"
                    log += f"Raw line from tcpdump: {line.strip()}\n"
                    log += f"Found domain: {domain}\n"
                    log += f"Found IP: {ip}\n"
                    if domain and ip:
                        log += f"Validation from API: {self.validate_ip(domain, ip)}\n"

                    print(log)
                    with open("dns_queries.log", "a") as f:
                        f.write(f"{log}\n")
            except queue.Empty:
                continue

    def start_monitoring(self):
        try:
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

# Entry point of the project
def main(verbose_logs_input):
    if os.geteuid() != 0:
        print("This script requires root privileges to run tcpdump.")
        print("Please run with sudo: sudo python3 dns_monitor.py")
        sys.exit(1)

    monitor = DNSMonitor(verbose_logs_input)
    monitor.start_monitoring()


if __name__ == "__main__":

    # Set up argument parser
    parser = argparse.ArgumentParser(description="DNS Monitoring Script")

    # Add arguments
    parser.add_argument('--verbose', action='store_true', help="Increase log verbosity")

    # Parse the arguments
    args = parser.parse_args()

    # Call main with parsed arguments
    main(args.verbose)

