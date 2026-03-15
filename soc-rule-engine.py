#!/usr/bin/env python3
import re
import sys
import json
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict

from soc_config import load_soc_config

config = load_soc_config()
DB_PATH = config.get("DB_PATH", "/var/lib/soc/soc_logs.db")

# TR: Korelasyon penceresi (dakika)
# EN: Correlation window (in minutes)
CORRELATION_WINDOW = 10

RULES = [
    {
        "id": "BRUTE_FORCE_SSH",
        "name": "SSH Brute Force",
        "seviye": "KRİTİK",
        "pattern": r"Failed password for .+ from (\d+\.\d+\.\d+\.\d+)",
        "threshold": 5,
        "window": 10,
        "aciklama": "10 dakika içinde 5+ başarısız SSH girişi",
        "aksiyon": "BAN"
    },
    {
        "id": "INVALID_USER_SSH",
        "name": "SSH Geçersiz Kullanıcı",
        "seviye": "YÜKSEK",
        "pattern": r"Invalid user .+ from (\d+\.\d+\.\d+\.\d+)",
        "threshold": 3,
        "window": 10,
        "aciklama": "Geçersiz kullanıcı adıyla SSH denemesi",
        "aksiyon": "BAN"
    },
    {
        "id": "SQL_INJECTION",
        "name": "SQL Injection",
        "seviye": "KRİTİK",
        "pattern": r"(UNION SELECT|OR '1'='1|DROP TABLE|INSERT INTO|information_schema|SLEEP\(|BENCHMARK\()",
        "threshold": 1,
        "window": 10,
        "aciklama": "SQL injection denemesi tespit edildi",
        "aksiyon": "BAN"
    },
    {
        "id": "WEBSHELL",
        "name": "Webshell Erişimi",
        "seviye": "KRİTİK",
        "pattern": r"(shell\.php|cmd=|exec=|system\(|passthru\(|webshell|c99\.php|r57\.php)",
        "threshold": 1,
        "window": 10,
        "aciklama": "Webshell erişim girişimi tespit edildi",
        "aksiyon": "BAN"
    },
    {
        "id": "XSS",
        "name": "XSS Saldırısı",
        "seviye": "YÜKSEK",
        "pattern": r"(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)",
        "threshold": 1,
        "window": 10,
        "aciklama": "Cross-site scripting denemesi",
        "aksiyon": "LOG"
    },
    {
        "id": "PATH_TRAVERSAL",
        "name": "Path Traversal",
        "seviye": "YÜKSEK",
        "pattern": r"(\.\./|\.\.\\|%2e%2e|%252e)",
        "threshold": 2,
        "window": 10,
        "aciklama": "Dizin geçiş saldırısı denemesi",
        "aksiyon": "BAN"
    },
    {
        "id": "SCANNER",
        "name": "Otomatik Tarayıcı",
        "seviye": "KRİTİK",
        "pattern": r"(sqlmap|nikto|masscan|zgrab|nuclei|dirbuster|gobuster)",
        "threshold": 1,
        "window": 10,
        "aciklama": "Bilinen saldırı aracı tespit edildi",
        "aksiyon": "BAN"
    },
    {
        "id": "SENSITIVE_FILE",
        "name": "Hassas Dosya Erişimi",
        "seviye": "ORTA",
        "pattern": r"(\.env|\.git|wp-config|/etc/passwd|id_rsa|\.htaccess)",
        "threshold": 2,
        "window": 10,
        "aciklama": "Hassas dosyaya erişim denemesi",
        "aksiyon": "LOG"
    },
    {
        "id": "PORT_SCAN",
        "name": "Port Tarama",
        "seviye": "DÜŞÜK",
        "pattern": r"UFW BLOCK.+SYN",
        "threshold": 50,
        "window": 10,
        "aciklama": "Yoğun port tarama girişimi (UFW tarafından engellendi)",
        "aksiyon": "LOG"
    },
    {
        "id": "HTTP_FLOOD",
        "name": "HTTP Flood",
        "seviye": "YÜKSEK",
        "pattern": r"(GET|POST|HEAD) .+ HTTP",
        "threshold": 100,
        "window": 2,
        "aciklama": "Yüksek istek sayısı - olası DDoS",
        "aksiyon": "LOG"
    },
]

def init_rule_tables():
    # TR: Tablo oluşturma soc-db-init.py'ye taşındı
    # EN: Table creation moved to soc-db-init.py
    pass

def apply_rules(log_text):
    results = []
    tarih = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    for rule in RULES:
        matches = re.findall(rule["pattern"], log_text, re.IGNORECASE)
        
        # TR: IP tabanlı kurallar için korelasyon (SSH brute force vb.)
        # EN: Correlation for IP-based rules (SSH brute force etc.)
        if rule["id"] in ["BRUTE_FORCE_SSH", "INVALID_USER_SSH"]:
            ip_counts = defaultdict(int)
            for ip in matches:
                ip_counts[ip] += 1
            
            for ip, count in ip_counts.items():
                if count >= rule["threshold"]:
                    result = {
                        "kural_id": rule["id"],
                        "kural_adi": f"{rule['name']} (IP: {ip})",
                        "seviye": rule["seviye"],
                        "aciklama": f"{ip} adresinden {count} deneme: {rule['aciklama']}",
                        "eslesen_sayi": count,
                        "aksiyon": rule["aksiyon"],
                        "ip": ip
                    }
                    results.append(result)
                    
                    c.execute('''
                        INSERT INTO kural_tespitleri 
                        (tarih, kural_id, kural_adi, seviye, aciklama, eslesen_sayi, aksiyon)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (tarih, rule["id"], result["kural_adi"], rule["seviye"],
                          result["aciklama"], count, rule["aksiyon"]))
        else:
            # TR: Genel kurallar (HTTP Flood, Port Scan vb.)
            # EN: General rules (HTTP Flood, Port Scan etc.)
            count = len(matches)
            if count >= rule["threshold"]:
                result = {
                    "kural_id": rule["id"],
                    "kural_adi": rule["name"],
                    "seviye": rule["seviye"],
                    "aciklama": rule["aciklama"],
                    "eslesen_sayi": count,
                    "aksiyon": rule["aksiyon"]
                }
                results.append(result)
                
                c.execute('''
                    INSERT INTO kural_tespitleri 
                    (tarih, kural_id, kural_adi, seviye, aciklama, eslesen_sayi, aksiyon)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (tarih, rule["id"], rule["name"], rule["seviye"],
                      rule["aciklama"], count, rule["aksiyon"]))
    
    conn.commit()
    conn.close()
    return results

def format_results(results):
    if not results:
        return "KURAL_TEMİZ"
    
    output = []
    for r in results:
        seviye_emoji = {
            "KRİTİK": "🚨",
            "YÜKSEK": "⚠️",
            "ORTA": "🔶",
            "DÜŞÜK": "🔷"
        }.get(r["seviye"], "ℹ️")
        
        output.append(
            f"[KURAL:{r['kural_id']}] {seviye_emoji} {r['seviye']}\n"
            f"  Kural: {r['kural_adi']}\n"
            f"  Eşleşme: {r['eslesen_sayi']} kez\n"
            f"  Açıklama: {r['aciklama']}\n"
            f"  Aksiyon: {r['aksiyon']}"
        )
    
    return "\n\n".join(output)

if __name__ == "__main__":
    init_rule_tables()
    log_text = sys.stdin.read()
    results = apply_rules(log_text)
    print(format_results(results))
    
    # KRİTİK kural varsa çıkış kodu 2
    if any(r["seviye"] == "KRİTİK" for r in results):
        sys.exit(2)
    # YÜKSEK varsa çıkış kodu 1
    elif any(r["seviye"] in ["YÜKSEK"] for r in results):
        sys.exit(1)
    else:
        sys.exit(0)
