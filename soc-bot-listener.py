#!/usr/bin/env python3
import urllib.request
import json
import subprocess
import sqlite3
import time
import re
from datetime import datetime, timedelta

from soc_config import load_soc_config

config = load_soc_config()
DB_PATH = config.get("DB_PATH", "/var/lib/soc/soc_logs.db")

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

# TR: Komut bazlı hız sınırlama (rate limiting)
# EN: Command-based rate limiting
_LAST_CMD_TIME = {}
_CMD_COOLDOWN = 3  # saniye / seconds


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
        print(f"API hatasi: {e}")
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

def execute_command(cmd, sebep):
    # TR: shell=False için komutu güvenli şekilde listeye çevir
    # EN: Safely convert command to list for shell=False
    import shlex
    try:
        cmd_list = shlex.split(cmd)
        if not cmd_list:
            return False, "Gecersiz komut."
            
        binary = cmd_list[0]
        # TR: Sadece tam yol üzerinden veya kesin eşleşen binary'leri kabul et
        # EN: Only accept exact binary matches or full paths
        if binary not in ALLOWED_BINARIES:
            return False, f"Bu binary izin listesinde degil: {binary}"
    except Exception as e:
        return False, f"Komut ayristirma hatasi: {e}"
    
    try:
        # TR: shell=False için komutu listeye çevir
        # EN: Convert command to list for shell=False
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
        # TR: Tablo oluşturma soc-db-init.py'ye taşındı, burada sadece ekliyoruz
        # EN: Table creation moved to soc-db-init.py, just inserting here
        c.execute(
            "INSERT INTO komut_gecmisi (tarih, komut, sebep, sonuc, onaylayan) VALUES (?,?,?,?,?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), cmd, sebep,
             result.stdout + result.stderr, "telegram")
        )
        conn.commit()
        conn.close()
        return True, result.stdout or "Komut calistirildi."
    except Exception as e:
        return False, str(e)

def get_pending_command(pending_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT komut, sebep, message_id, chat_id, tarih FROM bekleyen_komutlar WHERE id=? AND durum='bekliyor'",
        (pending_id,)
    )
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    tarih = datetime.strptime(row[4], "%Y-%m-%d %H:%M:%S")
    if datetime.now() - tarih > timedelta(minutes=30):
        update_pending_status(pending_id, "suresi_doldu")
        return None
    return row[:4]

def update_pending_status(pending_id, durum):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE bekleyen_komutlar SET durum=? WHERE id=?", (durum, pending_id))
    conn.commit()
    conn.close()

# ─── TR: KOMUT HANDLERLARI / EN: COMMAND HANDLERS ─────────────────────────

def cmd_yardim(token, chat_id):
    msg = (
        "SOC Bot Komutlari\n"
        "==================\n\n"
        "/log <saat>\n"
        "  Son X saatin log ozetini gosterir\n"
        "  Ornek: /log 2\n\n"
        "/durum\n"
        "  CPU, RAM, disk ve servis durumunu gosterir\n\n"
        "/banlist\n"
        "  Aktif ban listesini ve son banlamalari gosterir\n\n"
        "/ban <ip> <sure> <sebep>\n"
        "  IP adresini banlar\n"
        "  Sure: 1s=1saat, 1g=1gun, 7g=7gun, kalici\n"
        "  Ornek: /ban 1.2.3.4 7g brute_force\n\n"
        "/unban <ip>\n"
        "  IP adresinin banini kaldirir\n"
        "  Ornek: /unban 1.2.3.4\n\n"
        "/tehdit\n"
        "  Bugunun tespit edilen tehdit gecmisini gosterir\n\n"
        "/analiz\n"
        "  Aninda manuel log analizi baslatir\n\n"
        "/istatistik\n"
        "  Son 7 gunun guvenlik istatistiklerini gosterir\n\n"
        "/yardim\n"
        "  Bu yardim menusunu gosterir"
    )
    send_message(token, chat_id, msg)

def cmd_log(token, chat_id, args):
    saat = 1
    if args:
        import re as _re
        m = _re.match(r'^(\d+)$', args.strip())
        if m:
            saat = int(m.group(1))
    saat = min(max(saat, 1), 24)
    since = (datetime.now() - timedelta(hours=saat)).strftime("%Y-%m-%d %H:%M:%S")

    result = ""
    try:
        # TR: Pipe gerektiren komutlar shell=True zorunlu
        # EN: Pipe commands require shell=True
        # TR: Tüm değerler sabit, kullanıcı girdisi yok
        # EN: All values are static, no user input
        r = subprocess.run(
            "tail -n 200 /var/log/nginx/access.log | grep -vE '\" (444|403|301|302) ' | tail -20",
            shell=True, capture_output=True, text=True, timeout=10
        )
        if r.stdout.strip():
            result += f"NGINX (son {saat}s):\n{r.stdout[:800]}\n\n"

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
            result = f"Son {saat} saatte dikkat cekici log bulunamadi."

    except subprocess.TimeoutExpired:
        result = "Komut zaman asimina ugradi."
    except Exception as e:
        result = f"Hata: {e}"

    send_message(token, chat_id, f"Log Ozeti - Son {saat} Saat\n{'='*25}\n{result}")

def cmd_durum(token, chat_id):
    try:
        disk = subprocess.run("df -h / | tail -1", shell=True, capture_output=True, text=True).stdout.strip()
        ram = subprocess.run("free -h | grep Mem", shell=True, capture_output=True, text=True).stdout.strip()
        cpu = subprocess.run("uptime", shell=True, capture_output=True, text=True).stdout.strip()
        nginx = subprocess.run("systemctl is-active nginx", shell=True, capture_output=True, text=True).stdout.strip()
        ssh_s = subprocess.run("systemctl is-active ssh", shell=True, capture_output=True, text=True).stdout.strip()
        bot = subprocess.run("systemctl is-active soc-bot-listener", shell=True, capture_output=True, text=True).stdout.strip()
        msg = (f"Sistem Durumu\n{'='*25}\n"
               f"Disk: {disk}\n"
               f"RAM: {ram}\n"
               f"Uptime: {cpu}\n\n"
               f"Servisler:\n"
               f"  nginx: {nginx}\n"
              f"  ssh: {ssh_s}\n"
               f"  soc-bot: {bot}\n"
               f"Saat: {datetime.now().strftime('%d/%m/%Y %H:%M')}")
        send_message(token, chat_id, msg)
    except Exception as e:
        send_message(token, chat_id, f"Hata: {e}")

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
        c.execute("SELECT tarih, sebep, kural_id FROM ban_gecmisi ORDER BY id DESC LIMIT 10")
        rows = c.fetchall()
        conn.close()

        msg = f"Aktif Ban Listesi ({len(lines)} IP)\n{'='*25}\n"
        for ip in lines[:20]:
            msg += f"  {ip}\n"
        if len(lines) > 20:
            msg += f"  ... ve {len(lines)-20} tane daha\n"

        if rows:
            msg += f"\nSon Banlamalar:\n"
            for row in rows:
                msg += f"  {row[0][:16]} | {row[2]} | {row[1]}\n"

        send_message(token, chat_id, msg)
    except Exception as e:
        send_message(token, chat_id, f"Hata: {e}")

def cmd_ban(token, chat_id, args):
    if not args:
        send_message(token, chat_id, "Kullanim: /ban <ip> <sure> <sebep>\nOrnek: /ban 1.2.3.4 7g brute_force")
        return

    parts = args.strip().split(None, 2)
    if len(parts) < 2:
        send_message(token, chat_id, "Eksik parametre.\nKullanim: /ban <ip> <sure> <sebep>")
        return

    ip = parts[0]
    sure_str = parts[1].lower()
    sebep = parts[2] if len(parts) > 2 else "manuel_ban"

    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
        send_message(token, chat_id, f"Gecersiz IP formati: {ip}")
        return

    # TR: Cloudflare ve whitelist kontrolu
    # EN: Cloudflare and whitelist check
    skip = [
        "127.", "10.", "192.168.",
        "173.245.", "103.21.", "103.22.", "103.31.",
        "141.101.", "108.162.", "162.158.", "104.16.",
        "104.24.", "172.64.", "172.68.", "172.69.",
        "172.70.", "172.71.", "YOUR_SERVER_IP."
    ]
    if any(ip.startswith(p) for p in skip):
        send_message(token, chat_id, f"Bu IP banlanamaz (Cloudflare veya whitelist): {ip}")
        return

    # Sure hesapla
    sure_map = {
        "1s": "1 saat", "2s": "2 saat", "6s": "6 saat", "12s": "12 saat",
        "1g": "1 gun", "7g": "7 gun", "30g": "30 gun", "90g": "90 gun",
        "kalici": "kalici"
    }
    sure_label = sure_map.get(sure_str, sure_str)

    success, output = execute_command(
        f"/usr/local/bin/nginx-ban-ip.sh {ip}", sebep
    )

    if success:
        # TR: Veritabanına kaydet
        # EN: Save to database
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "INSERT INTO ban_gecmisi (tarih, sebep, kural_id, otomatik) VALUES (?,?,?,0)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), sebep, "MANUEL")
        )
        conn.commit()
        conn.close()
        send_message(token, chat_id,
            f"Ban uygulandi!\n"
            f"IP: {ip}\n"
            f"Sure: {sure_label}\n"
            f"Sebep: {sebep}\n"
            f"Saat: {datetime.now().strftime('%H:%M:%S')}")
    else:
        send_message(token, chat_id, f"Ban basarisiz: {output}")


def cmd_unban(token, chat_id, args):
    if not args:
        send_message(token, chat_id, "Kullanim: /unban <IP>")
        return
    ip = args.strip()
    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
        send_message(token, chat_id, "Gecersiz IP formati.")
        return
    success, output = execute_command(f"/usr/local/bin/nginx-unban-ip.sh {ip}", "telegram_unban")
    if success:
        send_message(token, chat_id, f"Ban kaldirildi: {ip}")
    else:
        send_message(token, chat_id, f"Hata: {output}")

def cmd_tehdit(token, chat_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        bugun = datetime.now().strftime("%Y-%m-%d")
        c.execute("""SELECT kategori, seviye, COUNT(*) as sayi
            FROM tehditler WHERE tarih LIKE ?
            GROUP BY kategori ORDER BY sayi DESC LIMIT 10""", (f"{bugun}%",))
        rows = c.fetchall()

        c.execute("""SELECT kural_adi, seviye, COUNT(*) as sayi
            FROM kural_tespitleri WHERE tarih LIKE ?
            GROUP BY kural_id ORDER BY sayi DESC LIMIT 5""", (f"{bugun}%",))
        kural_rows = c.fetchall()
        conn.close()

        emoji = {"KRİTİK": "🚨", "YÜKSEK": "⚠️", "ORTA": "🔶", "DÜŞÜK": "🔷", "TEMİZ": "✅"}
        msg = f"Tehdit Gecmisi - Bugun\n{'='*25}\n"

        if kural_rows:
            msg += "Kural Tespitleri:\n"
            for r in kural_rows:
                e = emoji.get(r[1], "ℹ️")
                msg += f"  {e} {r[0]}: {r[2]} kez\n"

        if rows:
            msg += "\nAI Tespitleri:\n"
            for r in rows:
                e = emoji.get(r[1], "ℹ️")
                msg += f"  {e} {r[0]}: {r[2]} kez\n"

        if not rows and not kural_rows:
            msg += "Bugun tehdit tespit edilmedi."

        send_message(token, chat_id, msg)
    except Exception as e:
        send_message(token, chat_id, f"Hata: {e}")

def cmd_analiz(token, chat_id):
    send_message(token, chat_id, "Manuel analiz baslatiliyor...")
    try:
        # TR: shell=True kaldirildi, komutlar ayri calistiriliyor
        # EN: shell=True removed, commands executed separately
        subprocess.run(["rm", "-f", "/var/lib/soc/last_run"], shell=False)
        result = subprocess.run(
            ["/usr/local/bin/soc-log-analyzer.sh"],
            shell=False, capture_output=True, text=True, timeout=120
        )
        output = result.stdout

        # Sadece ANALİZ SONUCU kısmını çıkar
        analiz = ""
        if "ANALİZ SONUCU" in output:
            idx = output.index("ANALİZ SONUCU")
            raw = output[idx:].strip()
            lines = []
            for line in raw.split('\n'):
                if any(x in line for x in ['Kaydedildi:', 'Bildirim', 'Telegram', 
                    'Model deneniyor', 'Analiz başarılı', 'byte log',
                    'Kural motoru', 'Otomatik ban', 'Ban uygulandı',
                    'Gönderildi:', '===']):
                    break
                lines.append(line)
            analiz = '\n'.join(lines).strip()
        
        if not analiz or len(analiz) < 10:
            analiz = "TEMİZ - Anormal aktivite tespit edilmedi."

        send_message(token, chat_id, f"Analiz Tamamlandi\n{'='*25}\n{analiz}")
    except subprocess.TimeoutExpired:
        send_message(token, chat_id, "Analiz zaman asimina ugradi (120s).")
    except Exception as e:
        send_message(token, chat_id, f"Hata: {e}")

def cmd_istatistik(token, chat_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""SELECT tarih, toplam_analiz, temiz, dusuk, orta, yuksek, kritik
            FROM istatistikler ORDER BY tarih DESC LIMIT 7""")
        rows = c.fetchall()
        conn.close()

        msg = f"Haftalik Istatistik\n{'='*25}\n"
        if rows:
            for r in rows:
                msg += (f"{r[0]}: "
                       f"Toplam:{r[1]} "
                       f"Temiz:{r[2]} "
                       f"Orta:{r[4]} "
                       f"Yuksek:{r[5]} "
                       f"Kritik:{r[6]}\n")
        else:
            msg += "Henuz istatistik yok."

        send_message(token, chat_id, msg)
    except Exception as e:
        send_message(token, chat_id, f"Hata: {e}")

def cmd_yardim(token, chat_id):
    msg = (
        "SOC Bot Komutlari\n"
        "==================\n"
        "/log <saat> - Log ozeti (orn: /log 2)\n"
        "/durum - Sistem durumu\n"
        "/banlist - Aktif ban listesi\n"
        "/unban <ip> - IP ban kaldir\n"
        "/tehdit - Bugunun tehdit gecmisi\n"
        "/analiz - Manuel analiz baslat\n"
        "/istatistik - Haftalik istatistik\n"
        "/yardim - Bu menu"
    )
    send_message(token, chat_id, msg)

# ─── TR: MESAJ YAKALAYICI / EN: MESSAGE HANDLER ───────────────────────────

def process_message(token, allowed_chat_id, message):
    chat_id = message["chat"]["id"]
    text = message.get("text", "").strip()

    if str(chat_id) != str(allowed_chat_id):
        send_message(token, chat_id, "Yetkisiz erisim.")
        return

    if not text.startswith("/"):
        return

    # TR: Hız sınırlama kontrolü
    # EN: Rate limit check
    now = time.time()
    if chat_id in _LAST_CMD_TIME:
        elapsed = now - _LAST_CMD_TIME[chat_id]
        if elapsed < _CMD_COOLDOWN:
            send_message(token, chat_id, f"⚠️ Cok hizli istek gonderiyorsunuz. Lutfen {int(_CMD_COOLDOWN - elapsed) + 1} saniye bekleyin.")
            return
    _LAST_CMD_TIME[chat_id] = now

    parts = text.split(None, 1)
    cmd = parts[0].lower().split("@")[0]
    args = parts[1] if len(parts) > 1 else ""

    if cmd == "/log":
        cmd_log(token, chat_id, args)
    elif cmd == "/durum":
        cmd_durum(token, chat_id)
    elif cmd == "/banlist":
        cmd_banlist(token, chat_id)
    elif cmd == "/unban":
        cmd_unban(token, chat_id, args)
    elif cmd == "/tehdit":
        cmd_tehdit(token, chat_id)
    elif cmd == "/analiz":
        cmd_analiz(token, chat_id)
    elif cmd == "/istatistik":
        cmd_istatistik(token, chat_id)
    elif cmd == "/ban":
        cmd_ban(token, chat_id, args)
    elif cmd == "/yardim" or cmd == "/start":
        cmd_yardim(token, chat_id)
    else:
        send_message(token, chat_id, f"Bilinmeyen komut: {cmd}\n/yardim yazin.")

# ─── TR: CALLBACK YAKALAYICI / EN: CALLBACK HANDLER ───────────────────────

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
        answer_callback(token, callback_id, "Bu komut artik gecerli degil.")
        return

    komut, sebep, orig_message_id, orig_chat_id = row

    if action == "ONAYLA":
        answer_callback(token, callback_id, "Komut calistiriliyor...")
        success, output = execute_command(komut, sebep)
        update_pending_status(pending_id, "onaylandi")
        if success:
            edit_message(token, chat_id, message_id,
                f"Komut calistirildi!\n\nKomut: {komut}\nCikti: {output[:300]}\nSaat: {datetime.now().strftime('%H:%M:%S')}")
        else:
            edit_message(token, chat_id, message_id,
                f"Komut basarisiz!\n\nKomut: {komut}\nHata: {output[:300]}")

    elif action == "REDDET":
        answer_callback(token, callback_id, "Komut iptal edildi.")
        update_pending_status(pending_id, "reddedildi")
        edit_message(token, chat_id, message_id,
            original_text + "\n\nReddedildi.")

# ─── INIT & MAIN ─────────────────────────────────────────────────

def init_db():
    # TR: Tablo baslatma işi soc-db-init.py tarafından yapılıyor
    # EN: Table initialization is handled by soc-db-init.py
    pass

def main():
    token = config.get("TELEGRAM_BOT_TOKEN")
    chat_id = config.get("TELEGRAM_CHAT_ID")
    init_db()
    print(f"[{datetime.now()}] SOC Bot Listener basladi...")

    # Bot komutlarini kaydet
    api_call(token, "setMyCommands", {"commands": [
        {"command": "log", "description": "Son X saatin log ozeti"},
        {"command": "durum", "description": "Sistem durumu"},
        {"command": "banlist", "description": "Aktif ban listesi"},
        {"command": "unban", "description": "IP ban kaldir"},
        {"command": "tehdit", "description": "Bugunun tehdit gecmisi"},
        {"command": "analiz", "description": "Manuel analiz baslat"},
        {"command": "istatistik", "description": "Haftalik istatistik"},
        {"command": "yardim", "description": "Komut listesi"},
        {"command": "ban", "description": "IP banla - /ban <ip> <sure> <sebep>"},    
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
                    process_message(token, chat_id, update["message"])

        except KeyboardInterrupt:
            print("Listener durduruldu.")
            break
        except Exception as e:
            print(f"Hata: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()
