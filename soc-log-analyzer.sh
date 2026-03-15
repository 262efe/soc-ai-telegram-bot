#!/bin/bash

source /etc/soc/config.env
mkdir -p /var/lib/soc

# GDPR/KVKK sensitive data masking
mask_sensitive() {
    sed -E 's/\b(([0-9]{1,3}\.){3})[0-9]{1,3}\b/\1XXX/g' | \
    sed -E 's/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[EMAIL_MASKED]/g' | \
    sed -E 's/(password|pass|pwd)=[^ &]*/\1=[PASS_MASKED]/gi' | \
    sed -E 's/Bearer [a-zA-Z0-9._-]+/Bearer [TOKEN_MASKED]/g'
}

# Track the last execution time
STATE_FILE="/var/lib/soc/last_run"
LAST_RUN=$(cat "$STATE_FILE" 2>/dev/null || echo "3 minutes ago")


collect_raw_logs() {
    local CF_PATTERN="173\.245\.|103\.21\.|103\.22\.|103\.31\.|141\.101\.|108\.162\.|190\.93\.|188\.114\.|197\.234\.|198\.41\.|162\.158\.|104\.1[6-9]\.|104\.2[0-4]\.|172\.6[4-9]\.|172\.7[0-1]\.|131\.0\.72\."
    local SERVER_IP="${SERVER_IP:-255.255.255.255}"

echo "=== NGINX ACCESS ==="
    awk -v since="$(date -d "$LAST_RUN" '+%d/%b/%Y:%H:%M:%S')" '
    {
        match($0, /\[([^\]]+)\]/, arr)
        if (arr[1] >= since) print
    }' /var/log/nginx/access.log 2>/dev/null | \
    grep -vE '" (444|403|301|302) ' | \
    grep -vE "$CF_PATTERN|$SERVER_IP"

    echo "=== AUTH/SSH ==="
    journalctl -u ssh --since "$LAST_RUN" 2>/dev/null
    awk -v since="$(date -d "$LAST_RUN" '+%b %d %H:%M')" '
    {
        if (substr($0,1,15) >= since) print
    }' /var/log/auth.log 2>/dev/null

    echo "=== UFW ==="
    journalctl -k --since "$LAST_RUN" 2>/dev/null | \
    grep "UFW BLOCK" | \
    grep -vE "SRC=($CF_PATTERN|$SERVER_IP)" | \
    tail -30
}


# Collect logs - only since the last execution
collect_logs() {
    # Cloudflare IP ranges - logs from these IPs are not sent to AI
    local CF_PATTERN="173\.245\.|103\.21\.|103\.22\.|103\.31\.|141\.101\.|108\.162\.|190\.93\.|188\.114\.|197\.234\.|198\.41\.|162\.158\.|104\.1[6-9]\.|104\.2[0-4]\.|172\.6[4-9]\.|172\.7[0-1]\.|131\.0\.72\."
    # Server's own IP
    local SERVER_IP="${SERVER_IP:-255.255.255.255}"

    echo "=== NGINX ERROR ==="
    awk -v since="$(date -d "$LAST_RUN" '+%Y/%m/%d %H:%M:%S')" '
    {
        if (substr($0,1,19) >= since) print
    }' /var/log/nginx/error.log 2>/dev/null | \
    grep -v "signal process\|graceful\|reopening" | \
    mask_sensitive

    echo "=== AUTH/SSH ==="
    journalctl -u ssh --since "$LAST_RUN" 2>/dev/null | \
    grep -v "session opened\|session closed\|pam_unix" | \
    mask_sensitive

    echo "=== SYSLOG ==="
    journalctl --since "$LAST_RUN" -p warning 2>/dev/null | \
    grep -v "sudo\|cron\|certbot\|systemd\|rsyslog\|logrotate\|CRON\|UFW" | \
    tail -8 | mask_sensitive

    echo "=== NGINX ACCESS ==="
    awk -v since="$(date -d "$LAST_RUN" '+%d/%b/%Y:%H:%M:%S')" '
    {
        match($0, /\[([^\]]+)\]/, arr)
        if (arr[1] >= since) print
    }' /var/log/nginx/access.log 2>/dev/null | \
    grep -vE '" (444|403|301|302) ' | \
    grep -vE "$CF_PATTERN|$SERVER_IP" | \
    mask_sensitive
}

# Collect raw logs for ban script
RAW_LOGS=$(collect_raw_logs)

# Rule engine running on RAW logs
echo "[$(date)] Rule engine running..."
RULE_OUTPUT=$(echo "$RAW_LOGS" | python3 /usr/local/bin/soc-rule-engine.py)
RULE_EXIT=$?

if [ "$RULE_OUTPUT" != "CLEAN" ]; then
    echo "$RULE_OUTPUT"
    if [ $RULE_EXIT -ge 1 ]; then
        echo "[$(date)] Automated ban starting..."
        printf "%s\n---RAW---\n%s" "$RULE_OUTPUT" "$RAW_LOGS" | python3 /usr/local/bin/soc-auto-ban.py
    fi
fi

# Send to Groq - retry + exponential backoff
# FIX: Instead of fetching the model list from the API, use the preferred list directly.
analyze_with_groq() {
    local logs="$1"

    # Declare and assign separately to avoid masking return values (SC2155)
    local prompt
    prompt="Analyze the following server logs. Report only real threats you detect.

Output format:
🔍 ANALYSIS RESULT
Date: $(date '+%d/%m/%Y %H:%M')

- Category: [name]
  Severity: [LOW/MEDIUM/HIGH/CRITICAL]
  Description: [description]
  Action: [action]

No threats: CLEAN

LOGS:
$logs"

    local preferred_models=(
        'moonshotai/kimi-k2-instruct'  # Best: Kimi K2 MoE (~1T)
        'llama-3.3-70b-versatile'      # 70B Llama
        'groq/compound'                # Medium: Groq compound
        'groq/compound-mini'           # Medium: Groq compound-mini
        'llama-3.1-8b-instant'         # Fallback: 8B smallest
    )

    local result=""
    local attempt=0

    for model in "${preferred_models[@]}"; do
        attempt=$((attempt + 1))
        echo "[$(date)] Attempting model ($attempt/${#preferred_models[@]}): $model" >&2

        result=$(curl -s -X POST "https://api.groq.com/openai/v1/chat/completions" \
            -H "Authorization: Bearer $GROQ_API_KEY" \
            -H "Content-Type: application/json" \
            -d "{
                \"model\": \"$model\",
                \"messages\": [{
                    \"role\": \"user\",
                    \"content\": $(echo "$prompt" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')
                }],
                \"max_tokens\": 1500,
                \"temperature\": 0.1
            }" | python3 -c "
import json,sys,re
data=json.load(sys.stdin)
if 'choices' in data:
    content=data['choices'][0]['message']['content'].strip()
    content=re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL|re.IGNORECASE).strip()
    if 'ANALYSIS RESULT' in content:
        content=content[content.index('ANALYSIS RESULT'):]
    if not content:
        print('EMPTY_RESPONSE')
    else:
        print(content)
elif 'error' in data:
    code=data['error'].get('code','')
    msg=data['error'].get('message','')
    if 'rate_limit' in code or 'rate_limit' in msg:
        print('RATE_LIMIT')
    elif 'model' in code or 'model_not_found' in code:
        print('MODEL_ERROR')
    else:
        print('API_ERROR:' + str(code))
else:
    print('UNKNOWN_ERROR')
")

# Success check — everything other than known error tokens is considered a success
        # EN: Success check — everything other than known error tokens is considered a success
        case "$result" in
            RATE_LIMIT|MODEL_ERROR|UNKNOWN_ERROR|EMPTY_RESPONSE|API_ERROR:*)
                local wait_secs
                wait_secs=$(( 2 ** attempt ))
                echo "[$(date)] $model failed ($result). Waiting ${wait_secs}s, trying next model..." >&2
                echo "[$(date)] MODEL_FAIL: $model -> $result" >> /var/log/soc-analyzer.log
                sleep "$wait_secs"
                ;;
            *)
                echo "[$(date)] Analysis successful: $model" >&2
                echo "$result"
                return 0
                ;;
        esac
    done
    # All models failed — return special token
    echo "[$(date)] CRITICAL: All Groq models failed!" >&2
    echo "[$(date)] ANALYSIS_ERROR: All models rejected" >> /var/log/soc-analyzer.log
    echo "ANALYSIS_FAILED"
    return 1
}

# Telegram notification
send_telegram() {
    local message="$1"
    local command="$2"
    local reason="$3"
    local truncated=$(echo "$message" | head -c 3500)

    python3 - << PYEOF
import urllib.request, json, sqlite3
from datetime import datetime

from soc_config import load_soc_config
config = load_soc_config()
token = config.get("TELEGRAM_BOT_TOKEN")
chat_id = config.get("TELEGRAM_CHAT_ID")
text = """$truncated"""
command = """$command"""
reason = """$reason"""
DB_PATH = "/var/lib/soc/soc_logs.db"

# Send message with buttons if command exists
if command and command.strip():
    # Send message first, get message_id
    payload = json.dumps({
        "chat_id": chat_id,
        "text": text + f"\n\n💻 Recommended Command:\n{command}"
    }).encode("utf-8")
    
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json; charset=utf-8"}
    )
    try:
        resp = urllib.request.urlopen(req)
        result = json.loads(resp.read().decode())
        message_id = result["result"]["message_id"]
        
        # Save pending command
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS pending_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, command TEXT, reason TEXT,
                message_id INTEGER, chat_id TEXT,
                status TEXT DEFAULT 'pending'
            )
        ''')
        c.execute('''
            INSERT INTO pending_commands (timestamp, command, reason, message_id, chat_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), command, reason, message_id, chat_id))
        conn.commit()
        pending_id = c.lastrowid
        conn.close()
        
        # Edit message with buttons
        edit_payload = json.dumps({
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text + f"\n\n💻 Recommended Command:\n{command}",
            "reply_markup": {
                "inline_keyboard": [[
                    {"text": "✅ Approve", "callback_data": f"soc_APPROVE_{pending_id}"},
                    {"text": "❌ Reject", "callback_data": f"soc_REJECT_{pending_id}"}
                ]]
            }
        }).encode("utf-8")
        
        edit_req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/editMessageText",
            data=edit_payload,
            headers={"Content-Type": "application/json; charset=utf-8"}
        )
        urllib.request.urlopen(edit_req)
        print("Telegram OK (with buttons)")
    except Exception as e:
        print(f"Telegram error: {e}")
else:
    # Basic message without buttons
    payload = json.dumps({
        "chat_id": chat_id,
        "text": text
    }).encode("utf-8")
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json; charset=utf-8"}
    )
    try:
        urllib.request.urlopen(req)
        print("Telegram OK")
    except Exception as e:
        print(f"Telegram error: {e}")
PYEOF
}

# Main flow
echo "[$(date)] SOC Log Analyzer started..."

LOGS=$(collect_logs)

# Use ${#LOGS} instead of echo | wc -c (SC2000)
LOG_SIZE=${#LOGS}
echo "[$(date)] $LOG_SIZE bytes of log collected"

# Truncate to 15000 bytes
if [ "$LOG_SIZE" -gt 15000 ]; then
    LOGS=$(echo "$LOGS" | head -c 15000)
    echo "[$(date)] Log truncated to 15000 bytes"
fi

ANALYSIS=$(analyze_with_groq "$LOGS")
GROQ_EXIT=$?
echo "[$(date)] Groq analysis completed"
echo "$ANALYSIS"

# FIX: Handle analysis failure
if [ "$ANALYSIS" = "ANALYSIS_FAILED" ] || [ $GROQ_EXIT -ne 0 ]; then
    # Notify if 30 minutes have passed since the last warning
    WARN_FILE="/var/lib/soc/last_warn"
    LAST_WARN=$(cat "$WARN_FILE" 2>/dev/null || echo "0")
    NOW_TS=$(date +%s)
    DIFF=$((NOW_TS - LAST_WARN))
    
    if [ $DIFF -gt 1800 ]; then
        send_telegram "⚠️ SOC System Warning

Groq AI log analysis failed.
Date: $(date '+%d/%m/%Y %H:%M')
Reason: All models received rate limit or API error.

📋 Rule engine continues to run.
🔧 Manual check may be required."
        echo "$NOW_TS" > "$WARN_FILE"
    fi
    echo "$(date -Iseconds)" > "$STATE_FILE"
    exit 0
fi


# Each threat sent as separate message
NOTIFICATION=0
ANALYSIS_FILE=$(mktemp /tmp/soc_analysis_XXXXXX)
RAW_FILE=$(mktemp /tmp/soc_raw_XXXXXX)
echo "$ANALYSIS" > "$ANALYSIS_FILE"
echo "$RAW_LOGS" > "$RAW_FILE"

python3 /usr/local/bin/soc-notifier.py "$ANALYSIS_FILE" "$RAW_FILE"

rm -f "$ANALYSIS_FILE" "$RAW_FILE"
NOTIFICATION=1


# Save to DB (GDPR/KVKK: not raw logs, only analysis result)
echo "$ANALYSIS" | python3 /usr/local/bin/soc-db-save.py "$LOG_SIZE" "$NOTIFICATION"

# Save the last run time at the end
echo "$(date -Iseconds)" > "$STATE_FILE"

