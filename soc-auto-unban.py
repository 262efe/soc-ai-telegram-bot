#!/usr/bin/env python3
"""
Automatically removes expired IP bans. Executed by cron every 30 minutes.
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

    # Find expired automatic bans that have a valid IP
    c.execute('''
        SELECT id, ip, rule_id, expiry
        FROM ban_log
        WHERE expiry IS NOT NULL
          AND expiry <= ?
          AND ip IS NOT NULL
          AND automatic = 1
    ''', (now,))

    expired = c.fetchall()

    if not expired:
        print(f"[{now}] No expired bans.")
        conn.close()
        return

    print(f"[{now}] {len(expired)} expired bans found, unbanning...")

    for row_id, ip, rule_id, expiry in expired:
        result = subprocess.run(
            ["/usr/local/bin/nginx-unban-ip.sh", ip],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            # Set ban expiration to NULL (prevent re-processing)
            c.execute("UPDATE ban_log SET expiry = NULL WHERE id = ?", (row_id,))
            print(f"✅ Unbanned: {ip} | Rule: {rule_id} | Expired at: {expiry}")
        else:
            print(f"❌ Unban error: {ip} | {result.stderr.strip()}")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    main()
