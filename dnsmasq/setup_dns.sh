#!/bin/bash

# Install dnsmasq if not already installed
apt-get update && apt-get install -y dnsmasq

# Add DNS entry for google.com to resolve to 1.1.1.1
echo 'address=/www.wikipedia.org/7.7.7.7' >> /etc/dnsmasq.conf

# Set dnsmasq to forward other queries to Google's public DNS (8.8.8.8)
echo 'server=8.8.8.8' >> /etc/dnsmasq.conf

# Set dnsmasq to listen on localhost (127.0.0.1)
echo 'listen-address=127.0.0.1' >> /etc/dnsmasq.conf

# Update /etc/resolv.conf to use localhost (dnsmasq) as the DNS resolver
echo 'nameserver 127.0.0.1' > /etc/resolv.conf

# Restart dnsmasq to apply changes
dnsmasq -k &
