#!/usr/bin/env python3
import re
import sys
import sqlite3
import subprocess
from datetime import datetime, timedelta

from soc_config import load_soc_config

config = load_soc_config()
DB_PATH = config.get("DB_PATH", "/var/lib/soc/soc_logs.db")
SERVER_IP = config.get("SERVER_IP", "")

CLOUDFLARE_RANGES = [
    "173.245.48.", "103.21.244.", "103.22.200.", "103.31.4.",
    "141.101.", "108.162.", "190.93.", "188.114.",
    "197.234.", "198.41.", "162.158.", "104.16.",
    "104.17.", "104.18.", "104.19.", "104.20.",
    "104.21.", "104.22.", "104.23.", "104.24.",
    "172.64.", "172.65.", "172.66.", "172.67.",
    "172.68.", "172.69.", "172.70.", "172.71.",
    "131.0.72."
]

WHITELIST = [
    "127.0.0.1",
    SERVER_IP
] if SERVER_IP else ["127.0.0.1"]

# TR: Kural ID -> (ban süresi gün, açıklama)
# EN: Rule ID -> (ban duration in days, description)
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
    "BRUTE_FORCE_SSH":  r"Failed password for .+ from (\d+\.\d+\.\d+\.\d+)",
    "INVALID_USER_SSH": r"Invalid user .+ from (\d+\.\d+\.\d+\.\d+)",
    "SQL_INJECTION":    r'^(\d+\.\d+\.\d+\.\d+).+(UNION SELECT|OR .1.=.1|information_schema|sqlmap)',
    "WEBSHELL":         r'^(\d+\.\d+\.\d+\.\d+).+(shell\.php|cmd=|webshell|c99|r57)',
    "PATH_TRAVERSAL":   r'^(\d+\.\d+\.\d+\.\d+).+(\.\./|%2e%2e)',
    "SCANNER":          r'^(\d+\.\d+\.\d+\.\d+).+(sqlmap|nikto|nmap|masscan|nuclei|dirbuster)',
    "XSS":              r'^(\d+\.\d+\.\d+\.\d+).+(<script|javascript:|onerror=)',
}

def is_cloudflare(ip):
    return any(ip.startswith(r) for r in CLOUDFLARE_RANGES)

def is_whitelisted(ip):
    return any(ip.startswith(w) for w in WHITELIST)

def extract_ips(raw_logs, rule_id):
    pattern = RULE_IP_PATTERNS.get(rule_id)
    if not pattern:
        return []
    ips = set()
    for line in raw_logs.split('\n'):
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            ips.add(match.group(1))
    return list(ips)

def ban_ip(ip, sebep, kural_id):
    if is_cloudflare(ip):
        print(f"Cloudflare IP atlandı: {ip}")
        return False
    if is_whitelisted(ip):
        print(f"Whitelist IP atlandı: {ip}")
        return False

    result = subprocess.run(
        ["/usr/local/bin/nginx-ban-ip.sh", ip],
        capture_output=True, text=True
    )

    if "Banlanan IP" in result.stdout or result.returncode == 0:
        gun = BAN_DURATIONS.get(kural_id, 1)
        ban_bitis = (datetime.now() + timedelta(days=gun)).strftime('%Y-%m-%d %H:%M:%S')

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            INSERT INTO ban_gecmisi (tarih, ip, sebep, kural_id, otomatik, ban_bitis)
            VALUES (?, ?, ?, ?, 1, ?)
        ''', (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), ip, sebep, kural_id, ban_bitis))
        conn.commit()
        conn.close()
        print(f"✅ Ban uygulandı: {ip} | Sebep: {sebep} | Süre: {gun} gün | Bitiş: {ban_bitis}")
        return True
    else:
        print(f"Ban hatası: {result.stderr}")
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
        match = re.search(r'\[KURAL:(\w+)\].*KRİTİK', line)
        if match:
            ban_rules.append(match.group(1))
        match2 = re.search(r'\[KURAL:(BRUTE_FORCE_SSH|INVALID_USER_SSH|PATH_TRAVERSAL|SCANNER)\].*YÜKSEK', line)
        if match2:
            ban_rules.append(match2.group(1))

    if not ban_rules:
        print("Ban gerektiren kural tetiklenmedi.")
        sys.exit(0)

    print(f"Ban gerektiren kurallar: {ban_rules}")

    banned_count = 0
    for kural_id in set(ban_rules):
        ips = extract_ips(raw_logs, kural_id)
        if not ips:
            print(f"{kural_id} için IP bulunamadı")
            continue
        for ip in ips:
            if ban_ip(ip, kural_id, kural_id):
                banned_count += 1

    print(f"Toplam banlanan IP: {banned_count}")
