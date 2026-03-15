#!/bin/bash

source /etc/soc/config.env
mkdir -p /var/lib/soc

# TR: KVKK (Kişisel Verilerin Korunması Kanunu) maskeleme
# EN: GDPR/KVKK sensitive data masking
mask_sensitive() {
    sed -E 's/\b(([0-9]{1,3}\.){3})[0-9]{1,3}\b/\1XXX/g' | \
    sed -E 's/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[EMAIL_MASKED]/g' | \
    sed -E 's/(password|pass|pwd)=[^ &]*/\1=[PASS_MASKED]/gi' | \
    sed -E 's/Bearer [a-zA-Z0-9._-]+/Bearer [TOKEN_MASKED]/g'
}

# TR: Son çalışma zamanını takip et
# EN: Track the last execution time
STATE_FILE="/var/lib/soc/last_run"
LAST_RUN=$(cat "$STATE_FILE" 2>/dev/null || echo "3 minutes ago")


collect_raw_logs() {
    local CF_PATTERN="173\.245\.|103\.21\.|103\.22\.|103\.31\.|141\.101\.|108\.162\.|190\.93\.|188\.114\.|197\.234\.|198\.41\.|162\.158\.|104\.1[6-9]\.|104\.2[0-4]\.|172\.6[4-9]\.|172\.7[0-1]\.|131\.0\.72\."
    local SERVER_IP="192\.168\.1\."

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


# TR: Log topla - sadece son çalışmadan bu yana
# EN: Collect logs - only since the last execution
collect_logs() {
    # TR: Cloudflare IP aralıkları - bu IP'lerden gelen loglar AI'a gönderilmez
    # EN: Cloudflare IP ranges - logs from these IPs are not sent to AI
    local CF_PATTERN="173\.245\.|103\.21\.|103\.22\.|103\.31\.|141\.101\.|108\.162\.|190\.93\.|188\.114\.|197\.234\.|198\.41\.|162\.158\.|104\.1[6-9]\.|104\.2[0-4]\.|172\.6[4-9]\.|172\.7[0-1]\.|131\.0\.72\."
    # TR: Sunucu kendi IP'si
    # EN: Server's own IP
    local SERVER_IP="${SERVER_IP:-192.168.1.}"

    echo "=== NGINX ACCESS ==="
    awk -v since="$(date -d "$LAST_RUN" '+%d/%b/%Y:%H:%M:%S')" '
    {
        match($0, /\[([^\]]+)\]/, arr)
        if (arr[1] >= since) print
    }' /var/log/nginx/access.log 2>/dev/null | \
    grep -vE '" (444|403|301|302) ' | \
    grep -vE "$CF_PATTERN|$SERVER_IP" | \
    mask_sensitive

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

echo "=== UFW ==="
    # UFW bloklari AI'a gonderilmiyor - kural motoru hallediyor
	

    echo "=== SYSLOG ==="
    journalctl --since "$LAST_RUN" -p warning 2>/dev/null | \
    grep -v "sudo\|cron\|certbot\|systemd\|rsyslog\|logrotate\|CRON\|UFW" | \
    tail -8 | mask_sensitive
}

# Ham logları topla (ban için maskelenmemiş)
RAW_LOGS=$(collect_raw_logs)

# Kural motoru HAM loglar üzerinde çalışır
echo "[$(date)] Kural motoru çalışıyor..."
RULE_OUTPUT=$(echo "$RAW_LOGS" | python3 /usr/local/bin/soc-rule-engine.py)
RULE_EXIT=$?

if [ "$RULE_OUTPUT" != "KURAL_TEMİZ" ]; then
    echo "$RULE_OUTPUT"
    if [ $RULE_EXIT -ge 1 ]; then
        echo "[$(date)] Otomatik ban başlatılıyor..."
        printf "%s\n---RAW---\n%s" "$RULE_OUTPUT" "$RAW_LOGS" | python3 /usr/local/bin/soc-auto-ban.py
    fi
fi

# TR: Groq'a gönder - tekrar deneme (retry) + asimptotik gecikme (exponential backoff)
# EN: Send to Groq - retry + exponential backoff
# TR: FIX: API'den model listesi çekmek yerine, preferred (tercih edilen) listeyi doğrudan kullan.
# EN: FIX: Instead of fetching the model list from the API, use the preferred list directly.
analyze_with_groq() {
    local logs="$1"

    # TR: Declare and assign separately to avoid masking return values (SC2155)
    # EN: Declare and assign separately to avoid masking return values (SC2155)
    local prompt
    prompt="Analyze the following server logs. Report only real threats you detect.

Output format:
🔍 ANALİZ SONUCU
Tarih: $(date '+%d/%m/%Y %H:%M')

- Kategori: [name]
  Seviye: [DÜŞÜK/ORTA/YÜKSEK/KRİTİK]
  Açıklama: [description]
  Aksiyon: [action]

No threats: TEMİZ

LOGS:
$logs"

    local preferred_models=(
        'moonshotai/kimi-k2-instruct'  # En iyi: Kimi K2 MoE (~1T)
        'llama-3.3-70b-versatile'      # 70B Llama
        'groq/compound'                # Orta: Groq compound
        'groq/compound-mini'           # Orta: Groq compound-mini
        'llama-3.1-8b-instant'         # Fallback: 8B en küçük
    )

    local result=""
    local attempt=0

    for model in "${preferred_models[@]}"; do
        attempt=$((attempt + 1))
        echo "[$(date)] Model deneniyor ($attempt/${#preferred_models[@]}): $model" >&2

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
    if 'ANALİZ SONUCU' in content:
        content=content[content.index('ANALİZ SONUCU'):]
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
        print('API_ERROR:' + code)
else:
    print('UNKNOWN_ERROR')
")

# TR: Başarı kontrolü — bilinen hata token'larının dışındaki her şey başarı sayılır
        # EN: Success check — everything other than known error tokens is considered a success
        case "$result" in
            RATE_LIMIT|MODEL_ERROR|UNKNOWN_ERROR|EMPTY_RESPONSE|API_ERROR:*)
                local wait_secs
                wait_secs=$(( 2 ** attempt ))
                echo "[$(date)] $model başarısız ($result). ${wait_secs}s bekleniyor, sonraki model deneniyor..." >&2
                echo "[$(date)] MODEL_FAIL: $model -> $result" >> /var/log/soc-analyzer.log
                sleep "$wait_secs"
                ;;
            *)
                echo "[$(date)] Analiz başarılı: $model" >&2
                echo "$result"
                return 0
                ;;
        esac
    done
    # TR: Tüm modeller başarısız — özel token döndür
    # EN: All models failed — return special token
    echo "[$(date)] KRITIK: Tüm Groq modelleri başarısız oldu!" >&2
    echo "[$(date)] ANALIZ_HATASI: Tüm modeller reddetti" >> /var/log/soc-analyzer.log
    echo "ANALIZ_BASARISIZ"
    return 1
}

# TR: Telegram bildirimi
# EN: Telegram notification
send_telegram() {
    local message="$1"
    local komut="$2"
    local sebep="$3"
    local truncated=$(echo "$message" | head -c 3500)

    python3 - << PYEOF
import urllib.request, json, sqlite3
from datetime import datetime

from soc_config import load_soc_config
config = load_soc_config()
token = config.get("TELEGRAM_BOT_TOKEN")
chat_id = config.get("TELEGRAM_CHAT_ID")
text = """$truncated"""
komut = """$komut"""
sebep = """$sebep"""
DB_PATH = "/var/lib/soc/soc_logs.db"

# Komut varsa butonlu mesaj gönder
if komut and komut.strip():
    # Önce mesajı gönder, message_id al
    payload = json.dumps({
        "chat_id": chat_id,
        "text": text + f"\n\n💻 Önerilen Komut:\n{komut}"
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
        
        # Bekleyen komutu kaydet
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS bekleyen_komutlar (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tarih TEXT, komut TEXT, sebep TEXT,
                message_id INTEGER, chat_id TEXT,
                durum TEXT DEFAULT 'bekliyor'
            )
        ''')
        c.execute('''
            INSERT INTO bekleyen_komutlar (tarih, komut, sebep, message_id, chat_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), komut, sebep, message_id, chat_id))
        conn.commit()
        pending_id = c.lastrowid
        conn.close()
        
        # Butonlu mesajı düzenle
        edit_payload = json.dumps({
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text + f"\n\n💻 Önerilen Komut:\n{komut}",
            "reply_markup": {
                "inline_keyboard": [[
                    {"text": "✅ Onayla", "callback_data": f"soc_ONAYLA_{pending_id}"},
                    {"text": "❌ Reddet", "callback_data": f"soc_REDDET_{pending_id}"}
                ]]
            }
        }).encode("utf-8")
        
        edit_req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/editMessageText",
            data=edit_payload,
            headers={"Content-Type": "application/json; charset=utf-8"}
        )
        urllib.request.urlopen(edit_req)
        print("Telegram OK (butonlu)")
    except Exception as e:
        print(f"Telegram hata: {e}")
else:
    # Butonsuz normal mesaj
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
        print(f"Telegram hata: {e}")
PYEOF
}

# Ana akış
echo "[$(date)] SOC Log Analyzer başladı..."

LOGS=$(collect_logs)

# TR: ${#LOGS} kullan, echo | wc -c yerine (SC2000)
# EN: Use ${#LOGS} instead of echo | wc -c (SC2000)
LOG_SIZE=${#LOGS}
echo "[$(date)] $LOG_SIZE byte log toplandı"

# 15000 byte'a kırp
if [ "$LOG_SIZE" -gt 15000 ]; then
    LOGS=$(echo "$LOGS" | head -c 15000)
    echo "[$(date)] Log 15000 byte'a kırpıldı"
fi

ANALYSIS=$(analyze_with_groq "$LOGS")
GROQ_EXIT=$?
echo "[$(date)] Groq analizi tamamlandı"
echo "$ANALYSIS"

# FIX: Analiz başarısız olduysa özel hata yönetimi
if [ "$ANALYSIS" = "ANALIZ_BASARISIZ" ] || [ $GROQ_EXIT -ne 0 ]; then
    # Son uyarıdan bu yana 30 dakika geçtiyse bildir
    WARN_FILE="/var/lib/soc/last_warn"
    LAST_WARN=$(cat "$WARN_FILE" 2>/dev/null || echo "0")
    NOW_TS=$(date +%s)
    DIFF=$((NOW_TS - LAST_WARN))
    
    if [ $DIFF -gt 1800 ]; then
        send_telegram "⚠️ SOC Sistem Uyarısı

Groq AI log analizi başarısız oldu.
Tarih: $(date '+%d/%m/%Y %H:%M')
Neden: Tüm modeller rate limit veya API hatası aldı.

📋 Kural motoru çalışmaya devam ediyor.
🔧 Manuel kontrol gerekebilir."
        echo "$NOW_TS" > "$WARN_FILE"
    fi
    echo "$(date -Iseconds)" > "$STATE_FILE"
    exit 0
fi


# Her tehdit için ayrı mesaj gönder
BILDIRIM=0
ANALYSIS_FILE=$(mktemp /tmp/soc_analysis_XXXXXX)
RAW_FILE=$(mktemp /tmp/soc_raw_XXXXXX)
echo "$ANALYSIS" > "$ANALYSIS_FILE"
echo "$RAW_LOGS" > "$RAW_FILE"

python3 /usr/local/bin/soc-notifier.py "$ANALYSIS_FILE" "$RAW_FILE"

rm -f "$ANALYSIS_FILE" "$RAW_FILE"
BILDIRIM=1


# TR: Veritabanına kaydet (KVKK: ham loglar değil, sadece analiz sonucu)
# EN: Save to DB (GDPR/KVKK: not raw logs, only analysis result)
echo "$ANALYSIS" | python3 /usr/local/bin/soc-db-save.py "$LOG_SIZE" "$BILDIRIM"

# Son çalışma zamanını en sona kaydet
echo "$(date -Iseconds)" > "$STATE_FILE"

