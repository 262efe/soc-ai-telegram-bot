#!/usr/bin/env python3
"""
TR: Süresi dolan IP banlarını otomatik olarak kaldırır. Cron tarafından her 30 dakikada bir çalıştırılır.
EN: Automatically removes expired IP bans. Executed by cron every 30 minutes.
"""
import sqlite3
import subprocess
from datetime import datetime

from soc_config import load_soc_config

config = load_soc_config()
DB_PATH = config.get("DB_PATH", "/var/lib/soc/soc_logs.db")

def main():
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # TR: Süresi dolmuş ve IP'si olan otomatik banları bul
    # EN: Find expired automatic bans that have a valid IP
    c.execute('''
        SELECT id, ip, kural_id, ban_bitis
        FROM ban_gecmisi
        WHERE ban_bitis IS NOT NULL
          AND ban_bitis <= ?
          AND ip IS NOT NULL
          AND otomatik = 1
    ''', (now,))

    expired = c.fetchall()

    if not expired:
        print(f"[{now}] Süresi dolan ban yok / No expired bans.")
        conn.close()
        return

    print(f"[{now}] {len(expired)} ban süresi doldu, kaldırılıyor... / expired bans found, unbanning...")

    for row_id, ip, kural_id, ban_bitis in expired:
        result = subprocess.run(
            ["/usr/local/bin/nginx-unban-ip.sh", ip],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            # TR: Ban bitişini NULL yap (bir daha işlenmesin)
            # EN: Set ban expiration to NULL (prevent re-processing)
            c.execute("UPDATE ban_gecmisi SET ban_bitis = NULL WHERE id = ?", (row_id,))
            print(f"✅ Ban kaldırıldı / Unbanned: {ip} | Kural / Rule: {kural_id} | Bitiş / Expired at: {ban_bitis}")
        else:
            print(f"❌ Unban hatası / Unban error: {ip} | {result.stderr.strip()}")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    main()
