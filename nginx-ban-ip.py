#!/usr/bin/env python3
import sys, os, subprocess, ipaddress, tempfile
from soc_config import load_soc_config

config = load_soc_config()
SERVER_IP = config.get("SERVER_IP", "")

CLOUDFLARE_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
]

WHITELIST = [
    "127.0.0.1",
    SERVER_IP
] if SERVER_IP else ["127.0.0.1"]


# Get the IP address to ban as an argument
if len(sys.argv) < 2:
    print("Usage: nginx-ban-ip.py <ip>")
    sys.exit(1)

ip_str = sys.argv[1]

# IP address validation
try:
    ip_obj = ipaddress.ip_address(ip_str)
    
    # Whitelist check
    if any(ip_str == w for w in WHITELIST):
        print(f"Whitelisted IP skipped: {ip_str}")
        sys.exit(0)
        
    # Cloudflare check
    cf_networks = [ipaddress.ip_network(r) for r in CLOUDFLARE_RANGES]
    if any(ip_obj in net for net in cf_networks):
        print(f"Cloudflare IP skipped: {ip_str}")
        sys.exit(0)

    # Error if trying to ban private IPs
    if ip_obj.is_private or ip_obj.is_loopback:
        print(f"Error: Private or loopback IP cannot be banned: {ip_str}")
        sys.exit(1)
except ValueError:
    print(f"Error: Invalid IP address: {ip_str}")
    sys.exit(1)

# Location of the Nginx blocked IPs file
fn = "/etc/nginx/snippets/blocked-ips.conf"
target_dir = os.path.dirname(fn)
if not os.path.exists(target_dir):
    os.makedirs(target_dir, exist_ok=True)

# Read file if it exists, otherwise create default header
content = ""
if os.path.exists(fn):
    with open(fn, 'r') as f:
        content = f.read()
else:
    content = "# SOC Blocked IPs\n"

deny_rule = f"deny {ip_str};"

# If the IP is already banned, exit the process
if deny_rule in content:
    print(f"IP already banned: {ip_str}")
    sys.exit(0)

# Read old lines, exclude 'allow all', and append the new ban
lines = [l for l in content.split("\n") if l.strip() not in ("allow all;", "") and deny_rule not in l]
lines.append(deny_rule)
lines.append("allow all;")

# Atomic Write - To prevent race conditions
fd, temp_path = tempfile.mkstemp(dir=target_dir, text=True)
try:
    with os.fdopen(fd, 'w') as tmp:
        tmp.write("\n".join(lines) + "\n")
    # File permissions (644)
    os.chmod(temp_path, 0o644)
    os.replace(temp_path, fn)
except Exception as e:
    if os.path.exists(temp_path):
        os.remove(temp_path)
    print(f"Write error: {e}")
    sys.exit(1)

# Reload Nginx (systemctl is more robust)
subprocess.run(["systemctl", "reload", "nginx"])
print(f"Successfully banned: {ip_str}")
