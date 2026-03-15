#!/bin/bash

# Get the IP address to ban as an argument
IP="$1"
# Location of the Nginx blocked IPs file
FILE=/etc/nginx/snippets/blocked-ips.conf

# Execute the banning process using the hardened Python script
python3 /usr/local/bin/nginx-ban-ip.py "$IP"
