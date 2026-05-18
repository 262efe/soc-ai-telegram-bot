#!/usr/bin/env python3
import os
import sys
import re
import json
import time
import subprocess
import urllib.request
from datetime import datetime, timedelta

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    # IDE and local repository execution
    from core.soc_config import load_soc_config
except ImportError:
    # Production flattened execution (/usr/local/bin)
    from soc_config import load_soc_config  # type: ignore

config = load_soc_config()
GROQ_API_KEY = config.get("GROQ_API_KEY")
SERVER_IP = config.get("SERVER_IP", "255.255.255.255")

STATE_FILE = "/var/lib/soc/last_run"
WARN_FILE = "/var/lib/soc/last_warn"
DB_PATH = "/var/lib/soc/soc_logs.db"

def mask_sensitive(text):
    text = re.sub(r'\b(([0-9]{1,3}\.){3})[0-9]{1,3}\b', r'\1XXX', text)
    text = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[EMAIL_MASKED]', text)
    text = re.sub(r'(?i)(password|pass|pwd)=[^ &]*', r'\1=[PASS_MASKED]', text)
    text = re.sub(r'Bearer [a-zA-Z0-9._-]+', 'Bearer [TOKEN_MASKED]', text)
    return text

def get_last_run():
    try:
        with open(STATE_FILE, "r") as f:
            return f.read().strip()
    except:
        return "3 minutes ago"

def run_cmd(cmd):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return res.stdout
    except:
        return ""

def collect_raw_logs(last_run):
    cf_pattern = r"173\.245\.|103\.21\.|103\.22\.|103\.31\.|141\.101\.|108\.162\.|190\.93\.|188\.114\.|197\.234\.|198\.41\.|162\.158\.|104\.1[6-9]\.|104\.2[0-4]\.|172\.6[4-9]\.|172\.7[0-1]\.|131\.0\.72\."
    
    date_str = run_cmd(f"date -d '{last_run}' '+%d/%b/%Y:%H:%M:%S'").strip()
    nginx_cmd = f"awk -v since='{date_str}' '{{ match($0, /\\[([^\\]]+)\\]/, arr); if (arr[1] >= since) print }}' /var/log/nginx/access.log 2>/dev/null | grep -vE '\" (444|403|301|302) ' | grep -vE '{cf_pattern}|{SERVER_IP}'"
    nginx_out = run_cmd(nginx_cmd)
    
    ssh_cmd1 = f"journalctl -u ssh --since '{last_run}' 2>/dev/null"
    date_str2 = run_cmd(f"date -d '{last_run}' '+%b %d %H:%M'").strip()
    ssh_cmd2 = f"awk -v since='{date_str2}' '{{ if (substr($0,1,15) >= since) print }}' /var/log/auth.log 2>/dev/null"
    ssh_out = run_cmd(ssh_cmd1) + "\n" + run_cmd(ssh_cmd2)
    
    ufw_cmd = f"journalctl -k --since '{last_run}' 2>/dev/null | grep 'UFW BLOCK' | grep -vE 'SRC=({cf_pattern}|{SERVER_IP})' | tail -30"
    ufw_out = run_cmd(ufw_cmd)
    
    return f"=== NGINX ACCESS ===\n{nginx_out}\n=== AUTH/SSH ===\n{ssh_out}\n=== UFW ===\n{ufw_out}"

def collect_logs(last_run):
    cf_pattern = r"173\.245\.|103\.21\.|103\.22\.|103\.31\.|141\.101\.|108\.162\.|190\.93\.|188\.114\.|197\.234\.|198\.41\.|162\.158\.|104\.1[6-9]\.|104\.2[0-4]\.|172\.6[4-9]\.|172\.7[0-1]\.|131\.0\.72\."
    
    date_str = run_cmd(f"date -d '{last_run}' '+%Y/%m/%d %H:%M:%S'").strip()
    nginx_err = run_cmd(f"awk -v since='{date_str}' '{{ if (substr($0,1,19) >= since) print }}' /var/log/nginx/error.log 2>/dev/null | grep -v 'signal process\\|graceful\\|reopening'")
    
    ssh_out = run_cmd(f"journalctl -u ssh --since '{last_run}' 2>/dev/null | grep -v 'session opened\\|session closed\\|pam_unix'")
    
    syslog = run_cmd(f"journalctl --since '{last_run}' -p warning 2>/dev/null | grep -v 'sudo\\|cron\\|certbot\\|systemd\\|rsyslog\\|logrotate\\|CRON\\|UFW' | tail -8")
    
    date_str2 = run_cmd(f"date -d '{last_run}' '+%d/%b/%Y:%H:%M:%S'").strip()
    nginx_acc = run_cmd(f"awk -v since='{date_str2}' '{{ match($0, /\\[([^\\]]+)\\]/, arr); if (arr[1] >= since) print }}' /var/log/nginx/access.log 2>/dev/null | grep -vE '\" (444|403|301|302) ' | grep -vE '{cf_pattern}|{SERVER_IP}'")
    
    logs = f"=== NGINX ERROR ===\n{mask_sensitive(nginx_err)}\n"
    logs += f"=== AUTH/SSH ===\n{mask_sensitive(ssh_out)}\n"
    logs += f"=== SYSLOG ===\n{mask_sensitive(syslog)}\n"
    logs += f"=== NGINX ACCESS ===\n{mask_sensitive(nginx_acc)}\n"
    return logs

def analyze_with_groq(logs):
    prompt = f"""Analyze the following server logs. Report only real threats you detect.

Output format:
🔍 ANALYSIS RESULT
Date: {datetime.now().strftime('%d/%m/%Y %H:%M')}

- Category: [name]
  Severity: [LOW/MEDIUM/HIGH/CRITICAL]
  Description: [description]
  Action: [action]

No threats: CLEAN

LOGS:
{logs}"""

    models = [
        'moonshotai/kimi-k2-instruct',
        'llama-3.3-70b-versatile',
        'groq/compound',
        'groq/compound-mini',
        'llama-3.1-8b-instant'
    ]
    
    for attempt, model in enumerate(models, 1):
        print(f"[{datetime.now()}] Attempting model ({attempt}/{len(models)}): {model}", file=sys.stderr)
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1500,
            "temperature": 0.1
        }
        req = urllib.request.Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=json.dumps(payload).encode(),
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
        )
        try:
            resp = urllib.request.urlopen(req, timeout=30)
            data = json.loads(resp.read().decode())
            if 'choices' in data:
                content = data['choices'][0]['message']['content'].strip()
                content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL|re.IGNORECASE).strip()
                if 'ANALYSIS RESULT' in content:
                    content = content[content.index('ANALYSIS RESULT'):]
                if not content:
                    raise Exception("EMPTY_RESPONSE")
                print(f"[{datetime.now()}] Analysis successful: {model}", file=sys.stderr)
                return content
        except Exception as e:
            wait_secs = 2 ** attempt
            print(f"[{datetime.now()}] {model} failed ({e}). Waiting {wait_secs}s...", file=sys.stderr)
            run_cmd(f"echo '[{datetime.now()}] MODEL_FAIL: {model} -> {e}' >> /var/log/soc-analyzer.log")
            time.sleep(wait_secs)
            
    print(f"[{datetime.now()}] CRITICAL: All Groq models failed!", file=sys.stderr)
    run_cmd(f"echo '[{datetime.now()}] ANALYSIS_ERROR: All models rejected' >> /var/log/soc-analyzer.log")
    return "ANALYSIS_FAILED"

def send_telegram(msg):
    token = config.get("TELEGRAM_BOT_TOKEN")
    chat_id = config.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return
    payload = json.dumps({"chat_id": chat_id, "text": msg}).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except:
        pass

def main():
    os.makedirs("/var/lib/soc", exist_ok=True)
    last_run = get_last_run()
    
    raw_logs = collect_raw_logs(last_run)
    print(f"[{datetime.now()}] Rule engine running...")
    rule_res = subprocess.run(["python3", "/usr/local/bin/soc-rule-engine.py"], input=raw_logs, text=True, capture_output=True)
    rule_output = rule_res.stdout.strip()
    rule_exit = rule_res.returncode
    
    if rule_output and rule_output != "CLEAN":
        print(rule_output)
        if rule_exit >= 1:
            print(f"[{datetime.now()}] Automated ban starting...")
            ban_in = f"{rule_output}\n---RAW---\n{raw_logs}"
            subprocess.run(["python3", "/usr/local/bin/soc-auto-ban.py"], input=ban_in, text=True)
            
    print(f"[{datetime.now()}] SOC Log Analyzer started...")
    logs = collect_logs(last_run)
    log_size = len(logs)
    print(f"[{datetime.now()}] {log_size} bytes of log collected")
    
    if log_size > 15000:
        logs = logs[:15000]
        print(f"[{datetime.now()}] Log truncated to 15000 bytes")
        
    analysis = analyze_with_groq(logs)
    print(f"[{datetime.now()}] Groq analysis completed")
    print(analysis)
    
    if analysis == "ANALYSIS_FAILED":
        try:
            with open(WARN_FILE, "r") as f:
                last_warn = int(f.read().strip())
        except:
            last_warn = 0
            
        now_ts = int(time.time())
        if now_ts - last_warn > 1800:
            send_telegram(f"⚠️ SOC System Warning\n\nGroq AI log analysis failed.\nDate: {datetime.now().strftime('%d/%m/%Y %H:%M')}\nReason: All models failed.\n\n📋 Rule engine continues to run.\n🔧 Manual check may be required.")
            with open(WARN_FILE, "w") as f:
                f.write(str(now_ts))
        with open(STATE_FILE, "w") as f:
            f.write(datetime.now().isoformat())
        sys.exit(0)
        
    # Notifications
    with open("/tmp/soc_analysis.tmp", "w") as f1, open("/tmp/soc_raw.tmp", "w") as f2:
        f1.write(analysis)
        f2.write(raw_logs)
        
    subprocess.run(["python3", "/usr/local/bin/soc-notifier.py", "/tmp/soc_analysis.tmp", "/tmp/soc_raw.tmp"])
    
    # DB Save
    subprocess.run(["python3", "/usr/local/bin/soc-db-save.py", str(log_size), "1"], input=analysis, text=True)
    
    with open(STATE_FILE, "w") as f:
        f.write(datetime.now().isoformat())

if __name__ == "__main__":
    main()
