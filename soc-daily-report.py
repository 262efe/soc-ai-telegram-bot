#!/usr/bin/env python3
import sqlite3
import urllib.request
import json
import os
from datetime import datetime, timedelta

from soc_config import load_soc_config

config = load_soc_config()
DB_PATH = config.get("DB_PATH", "/var/lib/soc/soc_logs.db")

def get_daily_stats(tarih):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # TR: Genel istatistik
    # EN: General statistics
    c.execute("SELECT * FROM istatistikler WHERE tarih = ?", (tarih,))
    stats = c.fetchone()
    
    # TR: Kural tespitleri
    # EN: Rule detections
    c.execute("""
        SELECT kural_adi, seviye, COUNT(*) as sayi 
        FROM kural_tespitleri 
        WHERE tarih LIKE ? 
        GROUP BY kural_id 
        ORDER BY sayi DESC
    """, (f"{tarih}%",))
    kural_stats = c.fetchall()
    
    # TR: Ban geçmişi
    # EN: Ban history
    c.execute("""
        SELECT COUNT(*) FROM ban_gecmisi WHERE tarih LIKE ?
    """, (f"{tarih}%",))
    ban_count = c.fetchone()[0]
    
    # TR: En yüksek tehditler
    # EN: Highest threats
    c.execute("""
        SELECT kategori, seviye, COUNT(*) as sayi
        FROM tehditler
        WHERE tarih LIKE ?
        GROUP BY kategori
        ORDER BY sayi DESC
        LIMIT 5
    """, (f"{tarih}%",))
    tehditler = c.fetchall()
    
    conn.close()
    return stats, kural_stats, ban_count, tehditler

def send_telegram(token, chat_id, message):
    payload = json.dumps({
        "chat_id": chat_id,
        "text": message
    }).encode("utf-8")
    
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json; charset=utf-8"}
    )
    try:
        urllib.request.urlopen(req)
        print("Günlük rapor Telegram'a gönderildi")
    except Exception as e:
        print(f"Telegram hatası: {e}")

def main():
    dun = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    bugun = datetime.now().strftime('%Y-%m-%d')
    
    # TR: Bugünün verisini al (sabah raporu için bugünü kullan)
    # EN: Get today's data (use today for the morning report)
    stats, kural_stats, ban_count, tehditler = get_daily_stats(bugun)
    
    seviye_emoji = {"TEMİZ": "✅", "DÜŞÜK": "🔷", "ORTA": "🔶", "YÜKSEK": "⚠️", "KRİTİK": "🚨"}
    
    rapor = f"""📊 GÜNLÜK GÜVENLİK RAPORU
Tarih: {bugun}
{'='*30}

📈 ANALİZ İSTATİSTİKLERİ
"""
    
    if stats:
        rapor += f"""• Toplam Analiz: {stats[2]}
- Temiz: {stats[3]} ✅
- Düşük: {stats[4]} 🔷
- Orta: {stats[5]} 🔶
- Yüksek: {stats[6]} ⚠️
- Kritik: {stats[7]} 🚨
"""
    else:
        rapor += "• Veri bulunamadı\n"
    
    rapor += f"\n🔒 OTOMATIK BAN\n• Bugün banlanan: {ban_count} IP\n"
    
    if kural_stats:
        rapor += "\n📋 KURAL TESPİTLERİ\n"
        for kural in kural_stats[:5]:
            emoji = seviye_emoji.get(kural[1], "ℹ️")
            rapor += f"• {kural[0]}: {kural[2]} kez {emoji}\n"
    
    if tehditler:
        rapor += "\n🎯 AI TESPİTLERİ\n"
        for t in tehditler:
            emoji = seviye_emoji.get(t[1], "ℹ️")
            rapor += f"• {t[0]}: {t[2]} kez {emoji}\n"
    
    rapor += f"\n⏰ Rapor: {datetime.now().strftime('%H:%M:%S')}"
    
    send_telegram(config["TELEGRAM_BOT_TOKEN"], config["TELEGRAM_CHAT_ID"], rapor)

if __name__ == "__main__":
    main()
