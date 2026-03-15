#!/usr/bin/env python3
import sys
import re
import json
import sqlite3
import urllib.request
from datetime import datetime

from soc_config import load_soc_config, CLOUDFLARE_PREFIXES

config = load_soc_config()
DB_PATH = config.get("DB_PATH", "/var/lib/soc/soc_logs.db")
SERVER_IP = config.get("SERVER_IP", "")

SKIP_PREFIXES = CLOUDFLARE_PREFIXES + (
    ["127.", "10.", "172.16.", "172.17."] +
    ([SERVER_IP] if SERVER_IP else [])
)


def extract_ip(raw_logs):
    """
    Extract valid IP addresses from raw logs (excluding whitelist and Cloudflare)
    """
    patterns = [
        r'^(\d+\.\d+\.\d+\.\d+)',
        r'from (\d+\.\d+\.\d+\.\d+)',
        r'SRC=(\d+\.\d+\.\d+\.\d+)',
    ]
    seen = set()
    for line in raw_logs.split('\n'):
        for pattern in patterns:
            m = re.search(pattern, line)
            if m:
                ip = m.group(1)
                if not any(ip.startswith(p) for p in SKIP_PREFIXES):
                    if ip not in seen:
                        seen.add(ip)
                        yield ip


def get_command_suggestion(action, category, raw_logs):
    """
    Suggest a terminal command based on threat category and action
    """
    a = action.lower()
    k = category.lower()

    # First, suggest a ban command based on the attack category
    attack_categories = [
        'sql', 'injection', 'webshell', 'brute', 'scanner',
        'attack', 'exploit', 'xss', 'traversal',
        'shell', 'malware', 'botnet', 'ddos'
    ]
    if any(s in k for s in attack_categories):
        for ip in extract_ip(raw_logs):
            return f"/usr/local/bin/nginx-ban-ip.sh {ip}"

    # Suggest a command based on the action
    if any(w in a for w in ['ban', 'block', 'deny', 'blacklist']):
        for ip in extract_ip(raw_logs):
            return f"/usr/local/bin/nginx-ban-ip.sh {ip}"

    if any(w in a for w in ['ufw', 'firewall']):
        for ip in extract_ip(raw_logs):
            return f"ufw deny from {ip}"

    if 'fail2ban' in a:
        return "systemctl restart fail2ban"

    if any(w in a for w in ['logrotate', 'rotate']):
        return "logrotate -f /etc/logrotate.conf"

    if any(w in a for w in ['nginx', 'web server']) and any(w in a for w in ['restart', 'reload']):
        return "nginx -t && systemctl reload nginx"

    if any(w in a for w in ['disk', 'storage', 'space', 'df']):
        return "df -h && du -sh /var/log/*"

    if any(w in a for w in ['ssh', 'rate limit']):
        return "ufw limit ssh"

    if any(w in a for w in ['rsyslog', 'syslog']):
        return "systemctl restart rsyslog"

    if any(w in a for w in ['install', 'add']):
        if 'fail2ban' in a:
            return "apt install -y fail2ban"
        elif 'crowdsec' in a:
            return "apt install -y crowdsec"

    if any(w in a for w in ['izin', 'permission', 'chmod']):
        return "ls -la /var/log/ && chmod 755 /var/log"

    if any(w in a for w in ['ssl', 'certificate', 'certbot']):
        return "certbot renew --dry-run"

    if any(w in a for w in ['control', 'check', 'inspect', 'monitor']):
        return "df -h && free -h && systemctl status nginx"

    return None


def send_message(token, chat_id, text, command=None, pending_id=None):
    """
    Send a message to Telegram, optionally with inline buttons
    """
    if command and pending_id:
        payload = {
            "chat_id": chat_id,
            "text": text,
            "reply_markup": {
                "inline_keyboard": [[
                    {"text": "✅ Approve", "callback_data": f"soc_APPROVE_{pending_id}"},
                    {"text": "❌ Reject", "callback_data": f"soc_REJECT_{pending_id}"}
                ]]
            }
        }
    else:
        payload = {"chat_id": chat_id, "text": text}

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=data,
        headers={"Content-Type": "application/json; charset=utf-8"}
    )
    try:
        resp = urllib.request.urlopen(req)
        return json.loads(resp.read().decode())
    except Exception as e:
        print(f"Telegram error: {e}")
        return None


def save_pending(db_path, command, reason, message_id, chat_id):
    """
    Save the pending command to the database
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS pending_commands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, command TEXT, reason TEXT,
        message_id INTEGER, chat_id TEXT,
        status TEXT DEFAULT 'pending'
    )''')
    c.execute(
        '''INSERT INTO pending_commands (timestamp, command, reason, message_id, chat_id)
           VALUES (?, ?, ?, ?, ?)''',
        (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), command, reason, message_id, str(chat_id))
    )
    conn.commit()
    lid = c.lastrowid
    conn.close()
    return lid


def parse_threats(text):
    """
    Parse threats from the analysis text
    """
    threats = []
    current = {}

    for line in text.split('\n'):
        line = line.strip()
        if line.startswith('- Category:'):
            if current and current.get('severity', '') in ['CRITICAL', 'HIGH', 'MEDIUM']:
                threats.append(current)
            current = {'category': line.split(':', 1)[1].strip()}
        elif line.startswith('Severity:') and current:
            current['severity'] = line.split(':', 1)[1].strip()
        elif line.startswith('Description:') and current:
            current['description'] = line.split(':', 1)[1].strip()
        elif line.startswith('Action:') and current:
            current['action'] = line.split(':', 1)[1].strip()

    if current and current.get('severity', '') in ['CRITICAL', 'HIGH', 'MEDIUM']:
        threats.append(current)

    return threats


def process_threats(token, chat_id, threats, raw_logs):
    """
    Process threats and send Telegram notifications
    """
    severity_emoji = {'CRITICAL': '🚨', 'HIGH': '⚠️', 'MEDIUM': '🔶'}

    for threat in threats:
        severity = threat.get('severity', '')
        emoji = severity_emoji.get(severity, '🔶')
        category = threat.get('category', '')
        description = threat.get('description', '')
        action = threat.get('action', '')

        command = get_command_suggestion(action, category, raw_logs)

        # Extract IP address from command
        ip = None
        if command:
            m = re.search(r'(\d+\.\d+\.\d+\.\d+)', command)
            if m:
                ip = m.group(1)

        msg = (f"{emoji} {severity} Severity Threat detected\n"
               f"{'='*28}\n"
               f"📂 {category}\n\n"
               f"📋 {description}\n\n"
               f"🎯 {action}\n"
               f"🕐 {datetime.now().strftime('%d/%m/%Y %H:%M')}")

        if ip:
            msg += f"\n🌐 IP: {ip}"
        if command:
            msg += f"\n💻 Command: {command}"

        result = send_message(token, chat_id, msg)

        if result and result.get('ok') and command:
            message_id = result['result']['message_id']
            pending_id = save_pending(DB_PATH, command, category, message_id, chat_id)

            # Update message with buttons
            edit_payload = {
                "chat_id": chat_id,
                "message_id": message_id,
                "text": msg,
                "reply_markup": {
                    "inline_keyboard": [[
                        {"text": "✅ Approve", "callback_data": f"soc_APPROVE_{pending_id}"},
                        {"text": "❌ Reject", "callback_data": f"soc_REJECT_{pending_id}"}
                    ]]
                }
            }
            data = json.dumps(edit_payload).encode("utf-8")
            req = urllib.request.Request(
                f"https://api.telegram.org/bot{token}/editMessageText",
                data=data,
                headers={"Content-Type": "application/json; charset=utf-8"}
            )
            try:
                urllib.request.urlopen(req)
                print(f"Sent: {severity} | {category} | IP: {ip}")
            except Exception as e:
                print(f"Edit error: {e}")
        else:
            print(f"Sent: {severity} | {category} (No IP)")


def main():
    """
    Main entry point - validate arguments and process threats
    """
    if len(sys.argv) < 3:
        print("Usage: soc-notifier.py <analysis_file> <raw_file>")
        sys.exit(1)

    analysis_file = sys.argv[1]
    raw_file = sys.argv[2]
    token = config.get("TELEGRAM_BOT_TOKEN")
    chat_id = config.get("TELEGRAM_CHAT_ID")

    if not token or not chat_id:
        print("Error: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not found in configuration.")
        sys.exit(1)

    # Read files
    try:
        text = open(analysis_file).read()
        raw_logs = open(raw_file).read()
    except FileNotFoundError as e:
        print(f"File not found: {e}")
        sys.exit(1)

    # Parse threats
    threats = parse_threats(text)

    if not threats:
        print("No threats requiring notification.")
        sys.exit(0)

    # Process threats and send notifications
    process_threats(token, chat_id, threats, raw_logs)


if __name__ == '__main__':
    main()