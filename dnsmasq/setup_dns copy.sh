#!/bin/bash

# Install dnsmasq if not already installed
apt-get update && apt-get install -y dnsmasq

# Add DNS entry for google.com to resolve to 1.1.1.1
echo 'address=/google.com/1.1.1.1' >> /etc/dnsmasq.conf

# Update /etc/resolv.conf to use localhost (dnsmasq) as the DNS resolver
echo 'nameserver 127.0.0.1' > /etc/resolv.conf

# Restart dnsmasq to apply changes
dnsmasq -k &