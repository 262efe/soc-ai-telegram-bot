#!/bin/bash
# Fetch latest Cloudflare IPs and update NGINX config

CONF_FILE="/etc/nginx/conf.d/cloudflare-real-ip.conf"
TEMP_FILE=$(mktemp)

echo "# Cloudflare IP ranges - restore real visitor IP" > "$TEMP_FILE"

# IPv4
for ip in $(curl -s https://www.cloudflare.com/ips-v4); do
    echo "set_real_ip_from $ip;" >> "$TEMP_FILE"
done

# IPv6
for ip in $(curl -s https://www.cloudflare.com/ips-v6); do
    echo "set_real_ip_from $ip;" >> "$TEMP_FILE"
done

echo "real_ip_header CF-Connecting-IP;" >> "$TEMP_FILE"
echo "real_ip_recursive on;" >> "$TEMP_FILE"

# Check if there are changes
if ! cmp -s "$TEMP_FILE" "$CONF_FILE"; then
    cat "$TEMP_FILE" > "$CONF_FILE"
    if nginx -t 2>/dev/null; then
        systemctl reload nginx
        echo "Cloudflare IPs updated and NGINX reloaded."
    else
        echo "ERROR: NGINX config invalid, reload cancelled."
    fi
else
    echo "No changes in Cloudflare IPs."
fi

rm -f "$TEMP_FILE"
