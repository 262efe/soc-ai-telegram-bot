#!/usr/bin/env python3
import re
import sys
import sqlite3
import subprocess
from datetime import datetime, timedelta

from soc_config import load_soc_config, CLOUDFLARE_PREFIXES

config = load_soc_config()
DB_PATH = config.get("DB_PATH", "/var/lib/soc/soc_logs.db")
SERVER_IP = config.get("SERVER_IP", "")

WHITELIST = [
    "127.0.0.1",
    SERVER_IP
] if SERVER_IP else ["127.0.0.1"]

# Rule ID -> (ban duration in days, description)
BAN_DURATIONS = {
    "BRUTE_FORCE_SSH":  7,
    "INVALID_USER_SSH": 1,
    "SQL_INJECTION":    7,
    "WEBSHELL":         90,
    "XSS":              1,
    "PATH_TRAVERSAL":   7,
    "SCANNER":          30,
    "HTTP_FLOOD":       1,
}

RULE_IP_PATTERNS = {
    "BRUTE_FORCE_SSH":  re.compile(r"Failed password for .+ from (\d+\.\d+\.\d+\.\d+)", re.IGNORECASE),
    "INVALID_USER_SSH": re.compile(r"Invalid user .+ from (\d+\.\d+\.\d+\.\d+)", re.IGNORECASE),
    "SQL_INJECTION":    re.compile(r'^(\d+\.\d+\.\d+\.\d+).+(UNION SELECT|OR .1.=.1|information_schema|sqlmap)', re.IGNORECASE),
    "WEBSHELL":         re.compile(r'^(\d+\.\d+\.\d+\.\d+).+(shell\.php|cmd=|webshell|c99|r57)', re.IGNORECASE),
    "PATH_TRAVERSAL":   re.compile(r'^(\d+\.\d+\.\d+\.\d+).+(\.\./|%2e%2e)', re.IGNORECASE),
    "SCANNER":          re.compile(r'^(\d+\.\d+\.\d+\.\d+).+(sqlmap|nikto|nmap|masscan|nuclei|dirbuster)', re.IGNORECASE),
    "XSS":              re.compile(r'^(\d+\.\d+\.\d+\.\d+).+(<script|javascript:|onerror=)', re.IGNORECASE),
}


def is_cloudflare(ip):
    return any(ip.startswith(r) for r in CLOUDFLARE_PREFIXES)

def is_whitelisted(ip):
    return any(ip.startswith(w) for w in WHITELIST)

def extract_ips(raw_logs, rule_id):
    pattern = RULE_IP_PATTERNS.get(rule_id)
    if not pattern:
        return []
    ips = set()
    for line in raw_logs.split('\n'):
        match = pattern.search(line)
        if match:
            ips.add(match.group(1))
    return list(ips)

def ban_ip(ip, reason, rule_id):
    if is_cloudflare(ip):
        print(f"Cloudflare IP skipped: {ip}")
        return False
    if is_whitelisted(ip):
        print(f"Whitelisted IP skipped: {ip}")
        return False

    result = subprocess.run(
        ["/usr/local/bin/nginx-ban-ip.sh", ip],
        capture_output=True, text=True
    )

    if "Successfully banned" in result.stdout or result.returncode == 0:
        gun = BAN_DURATIONS.get(rule_id, 1)
        ban_bitis = (datetime.now() + timedelta(days=gun)).strftime('%Y-%m-%d %H:%M:%S')
        expiry = (datetime.now() + timedelta(days=gun)).strftime('%Y-%m-%d %H:%M:%S')

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            INSERT INTO ban_log (timestamp, ip, reason, rule_id, automatic, expiry)
            VALUES (?, ?, ?, ?, 1, ?)
        ''', (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), ip, reason, rule_id, expiry))
        conn.commit()
        conn.close()
        print(f"✅ Ban applied: {ip} | Reason: {reason} | Duration: {gun} days | End: {ban_bitis}")
        return True
    else:
        print(f"Ban error: {result.stderr}")
        return False

if __name__ == "__main__":
    content = sys.stdin.read()

    if "---RAW---" in content:
        rule_output, raw_logs = content.split("---RAW---", 1)
    else:
        rule_output = content
        raw_logs = ""

    ban_rules = []
    for line in rule_output.split('\n'):
        match = re.search(r'\[RULE:(\w+)\].*CRITICAL', line)
        if match:
            ban_rules.append(match.group(1))
        match2 = re.search(r'\[RULE:(BRUTE_FORCE_SSH|INVALID_USER_SSH|PATH_TRAVERSAL|SCANNER)\].*HIGH', line)
        if match2:
            ban_rules.append(match2.group(1))

    if not ban_rules:
        print("No rules requiring ban triggered.")
        sys.exit(0)

    print(f"Rules requiring ban: {ban_rules}")

    banned_count = 0
    for rule_id in set(ban_rules):
        ips = extract_ips(raw_logs, rule_id)
        if not ips:
            print(f"No IP found for {rule_id}")
            continue
        for ip in ips:
            if ban_ip(ip, rule_id, rule_id):
                banned_count += 1

    print(f"Total IPs banned: {banned_count}")
