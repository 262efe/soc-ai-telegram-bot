#!/usr/bin/env python3
import sys
import re
import json
import sqlite3
import urllib.request
from datetime import datetime

from soc_config import load_soc_config

config = load_soc_config()
DB_PATH = config.get("DB_PATH", "/var/lib/soc/soc_logs.db")
SERVER_IP = config.get("SERVER_IP", "")

SKIP_PREFIXES = [
    "127.", "10.", "192.168.", "172.16.", "172.17.",
    # TR: Cloudflare IP aralıkları
    # EN: Cloudflare IP ranges
    "173.245.", "103.21.", "103.22.", "103.31.",
    "141.101.", "108.162.", "190.93.", "188.114.",
    "197.234.", "198.41.",
    "162.158.", "162.159.",
    "104.16.", "104.17.", "104.18.", "104.19.",
    "104.20.", "104.21.", "104.22.", "104.23.", "104.24.",
    "172.64.", "172.65.", "172.66.", "172.67.",
    "172.68.", "172.69.", "172.70.", "172.71.",
    "131.0.72.",
    "2a06:98c0:",  # Cloudflare IPv6
] + ([SERVER_IP] if SERVER_IP else [])


def extract_ip(raw_logs):
    """
    TR: Ham loglardan geçerli IP adreslerini çıkar (whitelist ve Cloudflare hariç)
    EN: Extract valid IP addresses from raw logs (excluding whitelist and Cloudflare)
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


def get_command_suggestion(aksiyon, kategori, raw_logs):
    """
    TR: Tehdit kategorisi ve aksiyonuna göre terminal komutu öner
    EN: Suggest a terminal command based on threat category and action
    """
    a = aksiyon.lower()
    k = kategori.lower()

    # TR: Önce saldırı kategorisine göre ban komutu öner
    # EN: First, suggest a ban command based on the attack category
    saldiri_kategoriler = [
        'sql', 'injection', 'webshell', 'brute', 'scanner',
        'tarayici', 'saldiri', 'exploit', 'xss', 'traversal',
        'shell', 'malware', 'botnet', 'ddos'
    ]
    if any(s in k for s in saldiri_kategoriler):
        for ip in extract_ip(raw_logs):
            return f"/usr/local/bin/nginx-ban-ip.sh {ip}"

    # TR: Aksiyona göre komut öner
    # EN: Suggest a command based on the action
    if any(w in a for w in ['ban', 'engel', 'kara liste', 'block', 'deny', 'yasakla', 'blacklist']):
        for ip in extract_ip(raw_logs):
            return f"/usr/local/bin/nginx-ban-ip.sh {ip}"

    if any(w in a for w in ['ufw', 'güvenlik duvarı', 'firewall']):
        for ip in extract_ip(raw_logs):
            return f"ufw deny from {ip}"

    if 'fail2ban' in a:
        return "systemctl restart fail2ban"

    if any(w in a for w in ['logrotate', 'log rotasyon']):
        return "logrotate -f /etc/logrotate.conf"

    if any(w in a for w in ['nginx', 'web sunucu']) and any(w in a for w in ['yeniden', 'restart', 'reload']):
        return "nginx -t && systemctl reload nginx"

    if any(w in a for w in ['disk', 'depolama', 'alan', 'df']):
        return "df -h && du -sh /var/log/*"

    if any(w in a for w in ['ssh', 'rate limit']):
        return "ufw limit ssh"

    if any(w in a for w in ['rsyslog', 'syslog']):
        return "systemctl restart rsyslog"

    if any(w in a for w in ['kur', 'install', 'yükle']):
        if 'fail2ban' in a:
            return "apt install -y fail2ban"
        elif 'crowdsec' in a:
            return "apt install -y crowdsec"

    if any(w in a for w in ['izin', 'permission', 'chmod']):
        return "ls -la /var/log/ && chmod 755 /var/log"

    if any(w in a for w in ['ssl', 'sertifika', 'certbot']):
        return "certbot renew --dry-run"

    if any(w in a for w in ['kontrol', 'check', 'incele', 'izle']):
        return "df -h && free -h && systemctl status nginx"

    return None


def send_message(token, chat_id, text, komut=None, pending_id=None):
    """
    TR: Telegram'a mesaj gönder, isteğe bağlı inline butonlarla
    EN: Send a message to Telegram, optionally with inline buttons
    """
    if komut and pending_id:
        payload = {
            "chat_id": chat_id,
            "text": text,
            "reply_markup": {
                "inline_keyboard": [[
                    {"text": "✅ Onayla", "callback_data": f"soc_ONAYLA_{pending_id}"},
                    {"text": "❌ Reddet", "callback_data": f"soc_REDDET_{pending_id}"}
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
        print(f"Telegram hata: {e}")
        return None


def save_pending(db_path, komut, sebep, message_id, chat_id):
    """
    TR: Bekleyen komutu veritabanına kaydet
    EN: Save the pending command to the database
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS bekleyen_komutlar (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tarih TEXT, komut TEXT, sebep TEXT,
        message_id INTEGER, chat_id TEXT,
        durum TEXT DEFAULT 'bekliyor'
    )''')
    c.execute(
        '''INSERT INTO bekleyen_komutlar (tarih, komut, sebep, message_id, chat_id)
           VALUES (?, ?, ?, ?, ?)''',
        (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), komut, sebep, message_id, str(chat_id))
    )
    conn.commit()
    lid = c.lastrowid
    conn.close()
    return lid


def parse_threats(text):
    """
    TR: Analiz metninden tehditleri parse et
    EN: Parse threats from the analysis text
    """
    threats = []
    current = {}

    for line in text.split('\n'):
        line = line.strip()
        if line.startswith('- Kategori:'):
            if current and current.get('seviye', '') in ['KRİTİK', 'YÜKSEK', 'ORTA']:
                threats.append(current)
            current = {'kategori': line.split(':', 1)[1].strip()}
        elif line.startswith('Seviye:') and current:
            current['seviye'] = line.split(':', 1)[1].strip()
        elif line.startswith('Açıklama:') and current:
            current['aciklama'] = line.split(':', 1)[1].strip()
        elif line.startswith('Aksiyon:') and current:
            current['aksiyon'] = line.split(':', 1)[1].strip()

    if current and current.get('seviye', '') in ['KRİTİK', 'YÜKSEK', 'ORTA']:
        threats.append(current)

    return threats


def process_threats(token, chat_id, threats, raw_logs):
    """
    TR: Tehditleri işle ve Telegram'a bildirim gönder
    EN: Process threats and send Telegram notifications
    """
    seviye_emoji = {'KRİTİK': '🚨', 'YÜKSEK': '⚠️', 'ORTA': '🔶'}

    for threat in threats:
        seviye = threat.get('seviye', '')
        emoji = seviye_emoji.get(seviye, '🔶')
        kategori = threat.get('kategori', '')
        aciklama = threat.get('aciklama', '')
        aksiyon = threat.get('aksiyon', '')

        komut = get_command_suggestion(aksiyon, kategori, raw_logs)

        # TR: Komuttan IP adresini çıkar
        # EN: Extract IP address from command
        ip = None
        if komut:
            m = re.search(r'(\d+\.\d+\.\d+\.\d+)', komut)
            if m:
                ip = m.group(1)

        msg = (f"{emoji} {seviye} Seviye Tehdit\n"
               f"{'='*28}\n"
               f"📂 {kategori}\n\n"
               f"📋 {aciklama}\n\n"
               f"🎯 {aksiyon}\n"
               f"🕐 {datetime.now().strftime('%d/%m/%Y %H:%M')}")

        if ip:
            msg += f"\n🌐 IP: {ip}"
        if komut:
            msg += f"\n💻 Komut: {komut}"

        result = send_message(token, chat_id, msg)

        if result and result.get('ok') and komut:
            message_id = result['result']['message_id']
            pending_id = save_pending(DB_PATH, komut, kategori, message_id, chat_id)

            # TR: Mesajı butonlarla güncelle
            # EN: Update message with buttons
            edit_payload = {
                "chat_id": chat_id,
                "message_id": message_id,
                "text": msg,
                "reply_markup": {
                    "inline_keyboard": [[
                        {"text": "✅ Onayla", "callback_data": f"soc_ONAYLA_{pending_id}"},
                        {"text": "❌ Reddet", "callback_data": f"soc_REDDET_{pending_id}"}
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
                print(f"Gönderildi: {seviye} | {kategori} | IP: {ip}")
            except Exception as e:
                print(f"Edit hata: {e}")
        else:
            print(f"Gönderildi: {seviye} | {kategori} (IP yok)")


def main():
    """
    TR: Ana giriş noktası - argümanları doğrula ve tehditleri işle
    EN: Main entry point - validate arguments and process threats
    """
    if len(sys.argv) < 3:
        print("Kullanim: soc-notifier.py <analysis_file> <raw_file>")
        sys.exit(1)

    analysis_file = sys.argv[1]
    raw_file = sys.argv[2]
    token = config.get("TELEGRAM_BOT_TOKEN")
    chat_id = config.get("TELEGRAM_CHAT_ID")

    if not token or not chat_id:
        print("Hata: TELEGRAM_BOT_TOKEN veya TELEGRAM_CHAT_ID konfigürasyonda bulunamadı.")
        sys.exit(1)

    # TR: Dosyaları oku
    # EN: Read files
    try:
        text = open(analysis_file).read()
        raw_logs = open(raw_file).read()
    except FileNotFoundError as e:
        print(f"Dosya bulunamadı: {e}")
        sys.exit(1)

    # TR: Tehditleri parse et
    # EN: Parse threats
    threats = parse_threats(text)

    if not threats:
        print("Bildirim gerektiren tehdit yok.")
        sys.exit(0)

    # TR: Tehditleri işle ve bildirim gönder
    # EN: Process threats and send notifications
    process_threats(token, chat_id, threats, raw_logs)


if __name__ == '__main__':
    main()