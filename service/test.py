import requests

def resolve_with_cloudflare(ip, domain):
    url = f"http://{ip}/dns-query"
    headers = {"Accept": "application/dns-json"}
    params = {"name": domain, "type": "A"}  # Querying for A (IPv4) record
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        answers = data.get("Answer", [])
        ips = [answer["data"] for answer in answers if answer["type"] == 1]  # Type 1 = A record
        return ips
    except Exception as e:
        print(f"Error: {e}")
        return None

import socket

def parse_dns_query(data):
    """Parse the DNS query to extract the domain name."""
    try:
        # Skip the DNS header (12 bytes)
        query_start = 12
        domain_parts = []
        while True:
            length = data[query_start]
            if length == 0:
                break
            query_start += 1
            domain_parts.append(data[query_start:query_start + length].decode("utf-8"))
            query_start += length
        return ".".join(domain_parts)
    except Exception as e:
        print(f"Error parsing DNS query: {e}")
        return None

def monitor_dns():
    """Listen for DNS queries and print the requested domain."""
    # Create a UDP socket to listen on port 53
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 53))  # Bind to localhost on DNS port
        print("Listening for DNS queries on 127.0.0.1:53...")
        while True:
            data, addr = sock.recvfrom(512)  # Receive up to 512 bytes
            domain = parse_dns_query(data)
            if domain:
                print(f"User requested: {domain}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    monitor_dns()

# Example usage
cloudflare_API = "1.1.1.1"
domain_to_check = "google.com"
ips = resolve_with_cloudflare(cloudflare_API, domain_to_check)
if ips:
    print(f"The IPs for {domain_to_check} are: {ips}")
else:
    print("Failed to resolve.")
