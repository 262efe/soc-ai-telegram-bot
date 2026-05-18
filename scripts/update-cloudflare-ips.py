#!/usr/bin/env python3
import urllib.request
import subprocess
import sys

CONF_FILE = "/etc/nginx/conf.d/cloudflare-real-ip.conf"

def fetch_ips():
    ips = []
    try:
        resp4 = urllib.request.urlopen("https://www.cloudflare.com/ips-v4", timeout=10)
        ips.extend(resp4.read().decode().strip().split('\n'))
        
        resp6 = urllib.request.urlopen("https://www.cloudflare.com/ips-v6", timeout=10)
        ips.extend(resp6.read().decode().strip().split('\n'))
    except Exception as e:
        print(f"Error fetching Cloudflare IPs: {e}")
        sys.exit(1)
    return ips

def main():
    ips = fetch_ips()
    content = "# Cloudflare IP ranges - restore real visitor IP\n"
    for ip in ips:
        content += f"set_real_ip_from {ip};\n"
    
    content += "real_ip_header CF-Connecting-IP;\n"
    content += "real_ip_recursive on;\n"
    
    # Check if there are changes
    current_content = ""
    try:
        with open(CONF_FILE, "r") as f:
            current_content = f.read()
    except FileNotFoundError:
        pass

    if content != current_content:
        try:
            with open(CONF_FILE, "w") as f:
                f.write(content)
                
            nginx_test = subprocess.run(["nginx", "-t"], capture_output=True)
            if nginx_test.returncode == 0:
                subprocess.run(["systemctl", "reload", "nginx"])
                print("Cloudflare IPs updated and NGINX reloaded.")
            else:
                print("ERROR: NGINX config invalid, reload cancelled.")
        except PermissionError:
            print(f"Permission denied to write {CONF_FILE}. Please run as root.")
    else:
        print("No changes in Cloudflare IPs.")

if __name__ == "__main__":
    main()
