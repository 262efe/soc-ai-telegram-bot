#!/usr/bin/env python3
import sqlite3
import sys
import re
from datetime import datetime
from soc_config import load_soc_config

config = load_soc_config()
DB_PATH = config.get("DB_PATH", "/var/lib/soc/soc_logs.db")


def parse_analysis(analysis_text):
    """
    Parse the analysis text and extract threats
    """
    threats = []
    current = {}

    for line in analysis_text.split('\n'):
        line = line.strip()
        if line.startswith('- Category:') or line.startswith('• Category:'):
            if current:
                threats.append(current)
            current = {'category': line.split(':', 1)[1].strip()}
        elif line.startswith('Severity:') and current:
            current['severity'] = line.split(':', 1)[1].strip()
        elif line.startswith('Description:') and current:
            current['description'] = line.split(':', 1)[1].strip()
        elif line.startswith('Action:') and current:
            current['action'] = line.split(':', 1)[1].strip()

    if current:
        threats.append(current)

    return threats


def get_highest_severity(threats):
    """
    Find the highest threat severity
    """
    severity_order = ['CLEAN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    highest = 'CLEAN'

    for t in threats:
        severity = t.get('severity', 'CLEAN').upper()
        for s in severity_order:
            if s in severity and severity_order.index(s) > severity_order.index(highest):
                highest = s

    return highest


def mask_analysis(text):
    """
    Mask personal data before writing to database
    """
    # Mask IP addresses (last octet XXX)
    text = re.sub(
        r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}\b',
        r'\1XXX',
        text
    )
    # Mask IPv6 addresses
    text = re.sub(
        r'([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}',
        '[IPv6_MASKED]',
        text
    )
    # Mask email addresses
    text = re.sub(
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        '[EMAIL_MASKED]',
        text
    )
    # Mask password parameters
    text = re.sub(
        r'(password|pass|pwd)=[^ &]*',
        r'\1=[PASS_MASKED]',
        text,
        flags=re.IGNORECASE
    )
    # Mask Bearer tokens
    text = re.sub(
        r'Bearer [a-zA-Z0-9._-]+',
        'Bearer [TOKEN_MASKED]',
        text
    )
    return text


def save_analysis(analysis_text, log_size, notification_sent):
    # Apply extra masking before writing to database
    analysis_text = mask_analysis(analysis_text)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    threats = parse_analysis(analysis_text)
    highest = get_highest_severity(threats)

    # Save the main analysis
    c.execute('''
        INSERT INTO analyses (timestamp, raw_analysis, max_severity, notification_sent, log_size)
        VALUES (?, ?, ?, ?, ?)
    ''', (timestamp, analysis_text, highest, notification_sent, log_size))

    analysis_id = c.lastrowid

    # Save the threats
    for t in threats:
        severity = t.get('severity', 'CLEAN')
        if 'CLEAN' not in severity.upper():
            c.execute('''
                INSERT INTO threats (analysis_id, timestamp, category, severity, description, action)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                analysis_id, timestamp,
                t.get('category', ''),
                severity,
                t.get('description', ''),
                t.get('action', '')
            ))

    # Update daily statistics
    today = datetime.now().strftime('%Y-%m-%d')
    c.execute('SELECT id FROM statistics WHERE timestamp = ?', (today,))
    row = c.fetchone()

    # Validate column name from fixed list - SQL injection prevention
    VALID_COLUMNS = {'clean', 'low', 'medium', 'high', 'critical'}
    severity_col = {
        'CLEAN': 'clean', 'LOW': 'low',
        'MEDIUM': 'medium', 'HIGH': 'high', 'CRITICAL': 'critical'
    }.get(highest, 'clean')

    # Safety check - fall back to default if invalid column name
    if severity_col not in VALID_COLUMNS:
        severity_col = 'clean'

    if row:
        # Column name comes from fixed list so f-string is safe here
        c.execute(f'''
            UPDATE statistics
            SET total_analyses = total_analyses + 1, {severity_col} = {severity_col} + 1
            WHERE timestamp = ?
        ''', (today,))
    else:
        c.execute(f'''
            INSERT INTO statistics (timestamp, total_analyses, {severity_col})
            VALUES (?, 1, 1)
        ''', (today,))

    conn.commit()
    conn.close()

    print(f"Saved: {timestamp} | Severity: {highest} | "
          f"Threat count: {len([t for t in threats if 'CLEAN' not in t.get('severity', 'CLEAN').upper()])}")

if __name__ == '__main__':
    analysis_text = sys.stdin.read()
    log_size = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    notified = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    save_analysis(analysis_text, log_size, notified)