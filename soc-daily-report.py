#!/usr/bin/env python3
import sqlite3
import urllib.request
import json
import os
from datetime import datetime, timedelta

from soc_config import load_soc_config

config = load_soc_config()
DB_PATH = config.get("DB_PATH", "/var/lib/soc/soc_logs.db")

def get_daily_stats(date):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # General statistics
    c.execute("SELECT * FROM statistics WHERE timestamp = ?", (date,))
    stats = c.fetchone()
    
    # Rule detections
    c.execute("""
        SELECT rule_name, severity, COUNT(*) as match_count 
        FROM rule_detections 
        WHERE timestamp LIKE ? 
        GROUP BY rule_id 
        ORDER BY match_count DESC
    """, (f"{date}%",))
    rule_stats = c.fetchall()
    
    # Ban history
    c.execute("""
        SELECT COUNT(*) FROM ban_log WHERE timestamp LIKE ?
    """, (f"{date}%",))
    ban_count = c.fetchone()[0]
    
    # Highest threats
    c.execute("""
        SELECT category, severity, COUNT(*) as match_count
        FROM threats
        WHERE timestamp LIKE ?
        GROUP BY category
        ORDER BY match_count DESC
        LIMIT 5
    """, (f"{date}%",))
    threats = c.fetchall()
    
    conn.close()
    return stats, rule_stats, ban_count, threats

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
        print("Daily report sent to Telegram")
    except Exception as e:
        print(f"Telegram error: {e}")

def main():
    yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    today = datetime.now().strftime('%Y-%m-%d')
    
    # Get today's data (use today for report)
    stats, rule_stats, ban_count, threats = get_daily_stats(today)
    
    severity_emoji = {"CLEAN": "✅", "LOW": "🔷", "MEDIUM": "🔶", "HIGH": "⚠️", "CRITICAL": "🚨"}
    
    report = f"""📊 DAILY SECURITY REPORT
Date: {today}
{'='*30}

📈 ANALYSIS STATISTICS
"""
    
    if stats:
        report += f"""• Total Analyses: {stats[2]}
- Clean: {stats[3]} ✅
- Low: {stats[4]} 🔷
- Medium: {stats[5]} 🔶
- High: {stats[6]} ⚠️
- Critical: {stats[7]} 🚨
"""
    else:
        report += "• No data found\n"
    
    report += f"\n🔒 AUTOMATIC BAN\n• Banned today: {ban_count} IP\n"
    
    if rule_stats:
        report += "\n📋 RULE DETECTIONS\n"
        for rule in rule_stats[:5]:
            emoji = severity_emoji.get(rule[1], "ℹ️")
            report += f"• {rule[0]}: {rule[2]} times {emoji}\n"
    
    if threats:
        report += "\n🎯 AI DETECTIONS\n"
        for t in threats:
            emoji = severity_emoji.get(t[1], "ℹ️")
            report += f"• {t[0]}: {t[2]} times {emoji}\n"
    
    report += f"\n⏰ Report: {datetime.now().strftime('%H:%M:%S')}"
    
    send_telegram(config["TELEGRAM_BOT_TOKEN"], config["TELEGRAM_CHAT_ID"], report)

if __name__ == "__main__":
    main()
