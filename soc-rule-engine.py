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

# Correlation window (minutes)
CORRELATION_WINDOW = 10

RULES = [
    {
        "id": "BRUTE_FORCE_SSH",
        "name": "SSH Brute Force",
        "severity": "CRITICAL",
        "pattern": r"Failed password for .+ from (\d+\.\d+\.\d+\.\d+)",
        "threshold": 5,
        "window": 10,
        "description": "5+ failed SSH logins in 10 minutes",
        "action": "BAN"
    },
    {
        "id": "INVALID_USER_SSH",
        "name": "SSH Invalid User",
        "severity": "HIGH",
        "pattern": r"Invalid user .+ from (\d+\.\d+\.\d+\.\d+)",
        "threshold": 3,
        "window": 10,
        "description": "SSH attempt with invalid username",
        "action": "BAN"
    },
    {
        "id": "SQL_INJECTION",
        "name": "SQL Injection",
        "severity": "CRITICAL",
        "pattern": r"(UNION SELECT|OR '1'='1|DROP TABLE|INSERT INTO|information_schema|SLEEP\(|BENCHMARK\()",
        "threshold": 1,
        "window": 10,
        "description": "SQL injection attempt detected",
        "action": "BAN"
    },
    {
        "id": "WEBSHELL",
        "name": "Webshell Access",
        "severity": "CRITICAL",
        "pattern": r"(shell\.php|cmd=|exec=|system\(|passthru\(|webshell|c99\.php|r57\.php)",
        "threshold": 1,
        "window": 10,
        "description": "Webshell access attempt detected",
        "action": "BAN"
    },
    {
        "id": "XSS",
        "name": "XSS Attack",
        "severity": "HIGH",
        "pattern": r"(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)",
        "threshold": 1,
        "window": 10,
        "description": "Cross-site scripting attempt",
        "action": "LOG"
    },
    {
        "id": "PATH_TRAVERSAL",
        "name": "Path Traversal",
        "severity": "HIGH",
        "pattern": r"(\.\./|\.\.\\|%2e%2e|%252e)",
        "threshold": 2,
        "window": 10,
        "description": "Directory traversal attack attempt",
        "action": "BAN"
    },
    {
        "id": "SCANNER",
        "name": "Automated Scanner",
        "severity": "CRITICAL",
        "pattern": r"(sqlmap|nikto|masscan|zgrab|nuclei|dirbuster|gobuster)",
        "threshold": 1,
        "window": 10,
        "description": "Known attack tool detected",
        "action": "BAN"
    },
    {
        "id": "SENSITIVE_FILE",
        "name": "Sensitive File Access",
        "severity": "MEDIUM",
        "pattern": r"(\.env|\.git|wp-config|/etc/passwd|id_rsa|\.htaccess)",
        "threshold": 2,
        "window": 10,
        "description": "Attempt to access sensitive file",
        "action": "LOG"
    },
    {
        "id": "PORT_SCAN",
        "name": "Port Scan",
        "severity": "LOW",
        "pattern": r"UFW BLOCK.+SYN",
        "threshold": 50,
        "window": 10,
        "description": "Intense port scan attempt (blocked by UFW)",
        "action": "LOG"
    },
    {
        "id": "HTTP_FLOOD",
        "name": "HTTP Flood",
        "severity": "HIGH",
        "pattern": r"(GET|POST|HEAD) .+ HTTP",
        "threshold": 100,
        "window": 2,
        "description": "High request count - possible DDoS",
        "action": "LOG"
    },
]

# Pre-compile regex patterns for performance optimization
for rule in RULES:
    rule["compiled_pattern"] = re.compile(rule["pattern"], re.IGNORECASE)



def apply_rules(log_text):
    results = []
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    for rule in RULES:
        matches = rule["compiled_pattern"].findall(log_text)
        
        # Correlation for IP-based rules (SSH brute force etc.)
        if rule["id"] in ["BRUTE_FORCE_SSH", "INVALID_USER_SSH"]:
            ip_counts = defaultdict(int)
            for ip in matches:
                ip_counts[ip] += 1
            
            for ip, count in ip_counts.items():
                if count >= rule["threshold"]:
                    result = {
                        "rule_id": rule["id"],
                        "rule_name": f"{rule['name']} (IP: {ip})",
                        "severity": rule["severity"],
                        "description": f"{ip} address {count} attempts: {rule['description']}",
                        "match_count": count,
                        "action": rule["action"],
                        "ip": ip
                    }
                    results.append(result)
                    
                    c.execute('''
                        INSERT INTO rule_detections 
                        (timestamp, rule_id, rule_name, severity, description, match_count, action)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (timestamp, rule["id"], result["rule_name"], rule["severity"],
                          result["description"], count, rule["action"]))
        else:
            # General rules (HTTP Flood, Port Scan etc.)
            count = len(matches)
            if count >= rule["threshold"]:
                result = {
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "match_count": count,
                    "action": rule["action"]
                }
                results.append(result)
                
                c.execute('''
                    INSERT INTO rule_detections 
                    (timestamp, rule_id, rule_name, severity, description, match_count, action)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (timestamp, rule["id"], rule["name"], rule["severity"],
                      rule["description"], count, rule["action"]))
    
    conn.commit()
    conn.close()
    return results

def format_results(results):
    if not results:
        return "CLEAN"
    
    output = []
    for r in results:
        severity_emoji = {
            "CRITICAL": "🚨",
            "HIGH": "⚠️",
            "MEDIUM": "🔶",
            "LOW": "🔷"
        }.get(r["severity"], "ℹ️")
        
        output.append(
            f"[RULE:{r['rule_id']}] {severity_emoji} {r['severity']}\n"
            f"  Rule: {r['rule_name']}\n"
            f"  Matches: {r['match_count']} times\n"
            f"  Description: {r['description']}\n"
            f"  Action: {r['action']}"
        )
    
    return "\n\n".join(output)

if __name__ == "__main__":
    log_text = sys.stdin.read()
    results = apply_rules(log_text)
    print(format_results(results))
    
    # Exit code 2 for CRITICAL rule
    if any(r["severity"] == "CRITICAL" for r in results):
        sys.exit(2)
    # Exit code 1 for HIGH severity
    elif any(r["severity"] in ["HIGH"] for r in results):
        sys.exit(1)
    else:
        sys.exit(0)
