#!/usr/bin/env python3
import sys, os, subprocess, ipaddress, tempfile
from soc_config import load_soc_config

config = load_soc_config()

# Get the IP address to be unbanned
if len(sys.argv) < 2:
    print("Usage: nginx-unban-ip.py <ip>")
    sys.exit(1)

ip_str = sys.argv[1]
fn = "/etc/nginx/snippets/blocked-ips.conf"
target_dir = os.path.dirname(fn)

# IP validation
try:
    ipaddress.ip_address(ip_str)
except ValueError:
    print(f"Error: Invalid IP address: {ip_str}")
    sys.exit(1)

# If file doesn't exist, exit without action
if not os.path.exists(fn):
    sys.exit(0)

deny_rule = f"deny {ip_str};"

# Filter out all rules except the banned IP and append 'allow all'
with open(fn, 'r') as f:
    content = f.read()

if deny_rule not in content:
    print(f"IP not banned: {ip_str}")
    sys.exit(0)

lines = [l for l in content.split("\n") if l.strip() not in ("allow all;", "") and deny_rule not in l]
lines.append("allow all;")

# Atomic Write
fd, temp_path = tempfile.mkstemp(dir=target_dir, text=True)
try:
    with os.fdopen(fd, 'w') as tmp:
        tmp.write("\n".join(lines) + "\n")
    os.chmod(temp_path, 0o644)
    os.replace(temp_path, fn)
except Exception as e:
    if os.path.exists(temp_path):
        os.remove(temp_path)
    print(f"Write error: {e}")
    sys.exit(1)

# Reload Nginx
subprocess.run(["systemctl", "reload", "nginx"])
print(f"Successfully unbanned: {ip_str}")
