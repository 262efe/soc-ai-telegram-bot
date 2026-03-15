#!/usr/bin/env python3
import urllib.request
import json
import subprocess
import sqlite3
import time
import re
from datetime import datetime, timedelta

from soc_config import load_soc_config, CLOUDFLARE_PREFIXES

config = load_soc_config()
DB_PATH = config.get("DB_PATH", "/var/lib/soc/soc_logs.db")
SERVER_IP = config.get("SERVER_IP", "")

ALLOWED_BINARIES = [
    "/usr/local/bin/nginx-ban-ip.sh",
    "/usr/local/bin/nginx-unban-ip.sh",
    "/usr/local/bin/soc-log-analyzer.sh",
    "/usr/sbin/ufw",
    "/bin/systemctl",
    "/usr/bin/systemctl",
    "/usr/sbin/nginx",
    "/usr/bin/logrotate",
    "/bin/df",
    "/usr/bin/df",
    "/usr/bin/du",
    "/usr/bin/free",
    "/bin/ls",
    "/usr/bin/ls",
    "/bin/chmod",
    "/usr/bin/chmod",
    "/usr/bin/certbot",
    "/usr/bin/apt",
]

# Command-based rate limiting
_LAST_CMD_TIME = {}
_CMD_COOLDOWN = 3  # seconds


def api_call(token, method, data=None):
    url = f"https://api.telegram.org/bot{token}/{method}"
    if data:
        payload = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json; charset=utf-8"}
        )
    else:
        req = urllib.request.Request(url)
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        return json.loads(resp.read().decode())
    except Exception as e:
        print(f"API error: {e}")
        return None

def send_message(token, chat_id, text):
    api_call(token, "sendMessage", {
        "chat_id": chat_id,
        "text": text[:4000]
    })

def answer_callback(token, callback_id, text):
    api_call(token, "answerCallbackQuery", {
        "callback_query_id": callback_id,
        "text": text,
        "show_alert": False
    })

def edit_message(token, chat_id, message_id, text):
    api_call(token, "editMessageText", {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": text[:4000]
    })

def execute_command(cmd, reason):
    # Safely convert command to list for shell=False
    import shlex
    try:
        cmd_list = shlex.split(cmd)
        if not cmd_list:
            return False, "Invalid command."
            
        binary = cmd_list[0]
        # Only accept exact binary matches or full paths
        if binary not in ALLOWED_BINARIES:
            return False, f"This binary is not in the allowed list: {binary}"
    except Exception as e:
        return False, f"Command parsing error: {e}"
    
    try:
        import shlex
        cmd_list = shlex.split(cmd)
        
        result = subprocess.run(
            cmd_list,
            shell=False,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "INSERT INTO command_history (timestamp, command, reason, result, approved_by) VALUES (?,?,?,?,?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), cmd, reason,
             result.stdout + result.stderr, "telegram")
        )
        conn.commit()
        conn.close()
        return True, result.stdout or "Command executed."
    except Exception as e:
        return False, str(e)

def get_pending_command(pending_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT command, reason, message_id, chat_id, timestamp FROM pending_commands WHERE id=? AND status='pending'",
        (pending_id,)
    )
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    timestamp = datetime.strptime(row[4], "%Y-%m-%d %H:%M:%S")
    if datetime.now() - timestamp > timedelta(minutes=30):
        update_pending_status(pending_id, "expired")
        return None
    return row[:4]

def update_pending_status(pending_id, status):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE pending_commands SET status=? WHERE id=?", (status, pending_id))
    conn.commit()
    conn.close()

# COMMAND HANDLERS


def cmd_log(token, chat_id, args):
    hours = 1
    if args:
        import re as _re
        m = _re.match(r'^(\d+)$', args.strip())
        if m:
            hours = int(m.group(1))
    hours = min(max(hours, 1), 24)
    since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

    result = ""
    try:
        r = subprocess.run(
            "tail -n 200 /var/log/nginx/access.log | grep -vE '\" (444|403|301|302) ' | tail -20",
            shell=True, capture_output=True, text=True, timeout=10
        )
        if r.stdout.strip():
            result += f"NGINX (last {hours}h):\n{r.stdout[:800]}\n\n"

        r2 = subprocess.run(
            f"journalctl -u ssh --since '{since}' 2>/dev/null | grep -iE 'failed|invalid|accepted' | tail -15",
            shell=True, capture_output=True, text=True, timeout=10
        )
        if r2.stdout.strip():
            result += f"SSH:\n{r2.stdout[:600]}\n\n"

        r3 = subprocess.run(
            f"journalctl -k --since '{since}' 2>/dev/null | grep UFW | tail -10",
            shell=True, capture_output=True, text=True, timeout=10
        )
        if r3.stdout.strip():
            result += f"UFW:\n{r3.stdout[:400]}\n"

        if not result:
            result = f"No noteworthy logs found in the last {hours} hours."

    except subprocess.TimeoutExpired:
        result = "Command timed out."
    except Exception as e:
        result = f"Error: {e}"

    send_message(token, chat_id, f"Log Summary - Last {hours} Hours\n{'='*25}\n{result}")

def cmd_durum(token, chat_id):
    try:
        disk = subprocess.run("df -h / | tail -1", shell=True, capture_output=True, text=True).stdout.strip()
        ram = subprocess.run("free -h | grep Mem", shell=True, capture_output=True, text=True).stdout.strip()
        cpu = subprocess.run("uptime", shell=True, capture_output=True, text=True).stdout.strip()
        nginx = subprocess.run("systemctl is-active nginx", shell=True, capture_output=True, text=True).stdout.strip()
        ssh_s = subprocess.run("systemctl is-active ssh", shell=True, capture_output=True, text=True).stdout.strip()
        bot = subprocess.run("systemctl is-active soc-bot-listener", shell=True, capture_output=True, text=True).stdout.strip()
        msg = (f"System Status\n{'='*25}\n"
               f"Disk: {disk}\n"
               f"RAM: {ram}\n"
               f"Uptime: {cpu}\n\n"
               f"Services:\n"
               f"  nginx: {nginx}\n"
               f"  ssh: {ssh_s}\n"
               f"  soc-bot: {bot}\n"
               f"Time: {datetime.now().strftime('%d/%m/%Y %H:%M')}")
        send_message(token, chat_id, msg)
    except Exception as e:
        send_message(token, chat_id, f"Error: {e}")

def cmd_banlist(token, chat_id):
    try:
        r = subprocess.run(
            "grep '^deny' /etc/nginx/snippets/blocked-ips.conf | grep -v 'allow'",
            shell=True, capture_output=True, text=True
        )
        lines = [l.replace('deny ', '').replace(';', '').strip()
                 for l in r.stdout.strip().split('\n') if l.strip()]

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT timestamp, reason, rule_id FROM ban_log ORDER BY id DESC LIMIT 10")
        rows = c.fetchall()
        conn.close()

        msg = f"Active Ban List ({len(lines)} IPs)\n{'='*25}\n"
        for ip in lines[:20]:
            msg += f"  {ip}\n"
        if len(lines) > 20:
            msg += f"  ... and {len(lines)-20} more\n"

        if rows:
            msg += f"\nRecent Bans:\n"
            for row in rows:
                msg += f"  {row[0][:16]} | {row[2]} | {row[1]}\n"

        send_message(token, chat_id, msg)
    except Exception as e:
        send_message(token, chat_id, f"Error: {e}")

def cmd_ban(token, chat_id, args):
    if not args:
        send_message(token, chat_id, "Usage: /ban <ip> <duration> <reason>\nExample: /ban 1.2.3.4 7d brute_force")
        return

    parts = args.strip().split(None, 2)
    if len(parts) < 2:
        send_message(token, chat_id, "Missing parameters.\nUsage: /ban <ip> <duration> <reason>")
        return

    ip = parts[0]
    duration_str = parts[1].lower()
    reason = parts[2] if len(parts) > 2 else "manual_ban"

    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
        send_message(token, chat_id, f"Invalid IP format: {ip}")
        return

    # Cloudflare and whitelist check
    skip = [
        "127.", "10.", "172.16.", "172.17.",
    ] + CLOUDFLARE_PREFIXES + ([SERVER_IP] if SERVER_IP else [])
    if any(ip.startswith(p) for p in skip):
        send_message(token, chat_id, f"This IP cannot be banned (Cloudflare or whitelist): {ip}")
        return

    # Calculate duration
    duration_map = {
        "1h": "1 hour", "2h": "2 hours", "6h": "6 hours", "12h": "12 hours",
        "1d": "1 day", "7d": "7 days", "30d": "30 days", "90d": "90 days",
        "permanent": "permanent"
    }
    duration_label = duration_map.get(duration_str, duration_str)

    success, output = execute_command(
        f"/usr/local/bin/nginx-ban-ip.sh {ip}", reason
    )

    if success:
        # Save to database
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "INSERT INTO ban_log (timestamp, ip, reason, rule_id, automatic) VALUES (?,?,?,?,0)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, reason, "MANUEL")
        )
        conn.commit()
        conn.close()
        send_message(token, chat_id,
            f"Ban applied!\n"
            f"IP: {ip}\n"
            f"Duration: {duration_label}\n"
            f"Reason: {reason}\n"
            f"Time: {datetime.now().strftime('%H:%M:%S')}")
    else:
        send_message(token, chat_id, f"Ban failed: {output}")


def cmd_unban(token, chat_id, args):
    if not args:
        send_message(token, chat_id, "Usage: /unban <IP>")
        return
    ip = args.strip()
    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
        send_message(token, chat_id, "Invalid IP format.")
        return
    success, output = execute_command(f"/usr/local/bin/nginx-unban-ip.sh {ip}", "telegram_unban")
    if success:
        send_message(token, chat_id, f"Ban removed: {ip}")
    else:
        send_message(token, chat_id, f"Error: {output}")

def cmd_threats(token, chat_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        today = datetime.now().strftime("%Y-%m-%d")
        c.execute("""SELECT category, severity, COUNT(*) as count
            FROM threats WHERE timestamp LIKE ?
            GROUP BY category ORDER BY count DESC LIMIT 10""", (f"{today}%",))
        rows = c.fetchall()

        c.execute("""SELECT rule_name, severity, COUNT(*) as count
            FROM rule_detections WHERE timestamp LIKE ?
            GROUP BY rule_id ORDER BY count DESC LIMIT 5""", (f"{today}%",))
        rule_rows = c.fetchall()
        conn.close()

        emoji = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "🔶", "LOW": "🔷", "CLEAN": "✅"}
        msg = f"Threat History - Today\n{'='*25}\n"

        if rule_rows:
            msg += "Rule Detections:\n"
            for r in rule_rows:
                e = emoji.get(r[1], "ℹ️")
                msg += f"  {e} {r[0]}: {r[2]} times\n"

        if rows:
            msg += "\nAI Detections:\n"
            for r in rows:
                e = emoji.get(r[1], "ℹ️")
                msg += f"  {e} {r[0]}: {r[2]} times\n"

        if not rows and not rule_rows:
            msg += "No threats detected today."

        send_message(token, chat_id, msg)
    except Exception as e:
        send_message(token, chat_id, f"Error: {e}")

def cmd_analyze(token, chat_id):
    send_message(token, chat_id, "Manual analysis starting...")
    try:
        # shell=True removed, commands executed separately
        subprocess.run(["rm", "-f", "/var/lib/soc/last_run"], shell=False)
        result = subprocess.run(
            ["/usr/local/bin/soc-log-analyzer.sh"],
            shell=False, capture_output=True, text=True, timeout=120
        )
        output = result.stdout

        # Extract only the ANALYSIS RESULT part
        analysis = ""
        if "ANALYSIS RESULT" in output:
            idx = output.index("ANALYSIS RESULT")
            raw = output[idx:].strip()
            lines = []
            for line in raw.split('\n'):
                if any(x in line for x in ['Saved:', 'Notification', 'Telegram', 
                    'Attempting model', 'Analysis successful', 'byte log',
                    'Rule engine', 'Automated ban', 'Ban applied',
                    'Sent:', '===']):
                    break
                lines.append(line)
            analysis = '\n'.join(lines).strip()
        
        if not analysis or len(analysis) < 10:
            analysis = "CLEAN - No abnormal activity detected."

        send_message(token, chat_id, f"Analysis Completed\n{'='*25}\n{analysis}")
    except subprocess.TimeoutExpired:
        send_message(token, chat_id, "Analysis timed out (120s).")
    except Exception as e:
        send_message(token, chat_id, f"Error: {e}")

def cmd_stats(token, chat_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""SELECT timestamp, total_analyses, clean, low, medium, high, critical
            FROM statistics ORDER BY timestamp DESC LIMIT 7""")
        rows = c.fetchall()
        conn.close()

        msg = f"Weekly Statistics\n{'='*25}\n"
        if rows:
            for r in rows:
                msg += (f"{r[0]}: "
                       f"Total:{r[1]} "
                       f"Clean:{r[2]} "
                       f"Medium:{r[4]} "
                       f"High:{r[5]} "
                       f"Critical:{r[6]}\n")
        else:
            msg += "No statistics yet."

        send_message(token, chat_id, msg)
    except Exception as e:
        send_message(token, chat_id, f"Error: {e}")

def cmd_help(token, chat_id):
    msg = (
        "SOC Bot Commands\n"
        "==================\n"
        "/log <hours> - Log summary (e.g. /log 2)\n"
        "/status - System status\n"
        "/banlist - Active ban list\n"
        "/unban <ip> - Remove IP ban\n"
        "/threats - Today's threat history\n"
        "/analyze - Start manual analysis\n"
        "/stats - Weekly statistics\n"
        "/help - This menu"
    )
    send_message(token, chat_id, msg)

# MESSAGE HANDLER

def process_message(token, allowed_chat_id, message):
    chat_id = message["chat"]["id"]
    text = message.get("text", "").strip()

    if str(chat_id) != str(allowed_chat_id):
        send_message(token, chat_id, "Unauthorized access.")
        return

    if not text.startswith("/"):
        return

    # Rate limit check
    now = time.time()
    if chat_id in _LAST_CMD_TIME:
        elapsed = now - _LAST_CMD_TIME[chat_id]
        if elapsed < _CMD_COOLDOWN:
            send_message(token, chat_id, f"⚠️ You are sending requests too fast. Please wait {int(_CMD_COOLDOWN - elapsed) + 1} seconds.")
            return
    _LAST_CMD_TIME[chat_id] = now

    parts = text.split(None, 1)
    cmd = parts[0].lower().split("@")[0]
    args = parts[1] if len(parts) > 1 else ""

    if cmd == "/log":
        cmd_log(token, chat_id, args)
    elif cmd == "/status":
        cmd_status(token, chat_id)
    elif cmd == "/banlist":
        cmd_banlist(token, chat_id)
    elif cmd == "/unban":
        cmd_unban(token, chat_id, args)
    elif cmd == "/threats":
        cmd_threats(token, chat_id)
    elif cmd == "/analyze":
        cmd_analyze(token, chat_id)
    elif cmd == "/stats":
        cmd_stats(token, chat_id)
    elif cmd == "/ban":
        cmd_ban(token, chat_id, args)
    elif cmd == "/help" or cmd == "/start":
        cmd_help(token, chat_id)
    else:
        send_message(token, chat_id, f"Unknown command: {cmd}\nType /help.")

# CALLBACK HANDLER

def process_callback(token, callback_query):
    data = callback_query.get("data", "")
    callback_id = callback_query["id"]
    chat_id = callback_query["message"]["chat"]["id"]
    message_id = callback_query["message"]["message_id"]
    original_text = callback_query["message"].get("text", "")

    if not data.startswith("soc_"):
        return

    parts = data.split("_", 2)
    if len(parts) < 3:
        return

    action = parts[1]
    pending_id = int(parts[2])

    row = get_pending_command(pending_id)
    if not row:
        answer_callback(token, callback_id, "This command is no longer valid.")
        return

    command, reason, orig_message_id, orig_chat_id = row

    if action == "APPROVE":
        answer_callback(token, callback_id, "Executing command...")
        success, output = execute_command(command, reason)
        update_pending_status(pending_id, "approved")
        if success:
            edit_message(token, chat_id, message_id,
                f"Command executed!\n\nCommand: {command}\nOutput: {output[:300]}\nTime: {datetime.now().strftime('%H:%M:%S')}")
        else:
            edit_message(token, chat_id, message_id,
                f"Command failed!\n\nCommand: {command}\nError: {output[:300]}")

    elif action == "REJECT":
        answer_callback(token, callback_id, "Command cancelled.")
        update_pending_status(pending_id, "rejected")
        edit_message(token, chat_id, message_id,
            original_text + "\n\nRejected.")

# ─── INIT & MAIN ─────────────────────────────────────────────────

def init_db():
    # Table initialization is handled by soc-db-init.py
    pass

def main():
    token = config.get("TELEGRAM_BOT_TOKEN")
    allowed_chat_id = config.get("TELEGRAM_CHAT_ID")
    init_db()
    print(f"[{datetime.now()}] SOC Bot Listener started...")

    # Register bot commands
    api_call(token, "setMyCommands", {"commands": [
        {"command": "log", "description": "Last X hours log summary"},
        {"command": "status", "description": "System status"},
        {"command": "banlist", "description": "Active ban list"},
        {"command": "unban", "description": "Remove IP ban"},
        {"command": "threats", "description": "Today's threat history"},
        {"command": "analyze", "description": "Start manual analysis"},
        {"command": "stats", "description": "Weekly statistics"},
        {"command": "help", "description": "Command list"},
        {"command": "ban", "description": "Ban IP - /ban <ip> <duration> <reason>"},    
]})

    offset = 0
    while True:
        try:
            result = api_call(token, "getUpdates", {
                "offset": offset,
                "timeout": 25,
                "allowed_updates": ["callback_query", "message"]
            })

            if not result or not result.get("ok"):
                time.sleep(5)
                continue

            for update in result.get("result", []):
                offset = update["update_id"] + 1
                if "callback_query" in update:
                    process_callback(token, update["callback_query"])
                elif "message" in update:
                    process_message(token, allowed_chat_id, update["message"])

        except KeyboardInterrupt:
            print("Listener stopped.")
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()
