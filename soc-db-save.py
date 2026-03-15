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
    TR: Analiz metnini parse et, tehditleri çıkar
    EN: Parse the analysis text and extract threats
    """
    threats = []
    current = {}

    for line in analysis_text.split('\n'):
        line = line.strip()
        if line.startswith('- Kategori:') or line.startswith('• Kategori:'):
            if current:
                threats.append(current)
            current = {'kategori': line.split(':', 1)[1].strip()}
        elif line.startswith('Seviye:') and current:
            current['seviye'] = line.split(':', 1)[1].strip()
        elif line.startswith('Açıklama:') and current:
            current['aciklama'] = line.split(':', 1)[1].strip()
        elif line.startswith('Aksiyon:') and current:
            current['aksiyon'] = line.split(':', 1)[1].strip()

    if current:
        threats.append(current)

    return threats


def get_highest_severity(threats):
    """
    TR: En yüksek tehdit seviyesini bul
    EN: Find the highest threat severity
    """
    severity_order = ['TEMİZ', 'DÜŞÜK', 'ORTA', 'YÜKSEK', 'KRİTİK']
    highest = 'TEMİZ'

    for t in threats:
        seviye = t.get('seviye', 'TEMİZ').upper()
        for s in severity_order:
            if s in seviye and severity_order.index(s) > severity_order.index(highest):
                highest = s

    return highest


def mask_analysis(text):
    """
    TR: Veritabanına yazmadan önce kişisel verileri maskele
    EN: Mask personal data before writing to database
    """
    # TR: IP adreslerini maskele (son oktet XXX)
    # EN: Mask IP addresses (last octet XXX)
    text = re.sub(
        r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}\b',
        r'\1XXX',
        text
    )
    # TR: E-posta adreslerini maskele
    # EN: Mask email addresses
    text = re.sub(
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        '[EMAIL_MASKED]',
        text
    )
    # TR: Şifre parametrelerini maskele
    # EN: Mask password parameters
    text = re.sub(
        r'(password|pass|pwd)=[^ &]*',
        r'\1=[PASS_MASKED]',
        text,
        flags=re.IGNORECASE
    )
    # TR: Bearer token'ları maskele
    # EN: Mask Bearer tokens
    text = re.sub(
        r'Bearer [a-zA-Z0-9._-]+',
        'Bearer [TOKEN_MASKED]',
        text
    )
    return text


def save_analysis(analysis_text, log_boyutu, bildirim_gonderildi):
    # TR: Veritabanına yazmadan önce ekstra maskeleme uygula
    # EN: Apply extra masking before writing to database
    analysis_text = mask_analysis(analysis_text)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    tarih = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    threats = parse_analysis(analysis_text)
    highest = get_highest_severity(threats)

    # TR: Ana analizi kaydet
    # EN: Save the main analysis
    c.execute('''
        INSERT INTO analizler (tarih, ham_analiz, en_yuksek_seviye, bildirim_gonderildi, log_boyutu)
        VALUES (?, ?, ?, ?, ?)
    ''', (tarih, analysis_text, highest, bildirim_gonderildi, log_boyutu))

    analiz_id = c.lastrowid

    # TR: Tehditleri kaydet
    # EN: Save the threats
    for t in threats:
        seviye = t.get('seviye', 'TEMİZ')
        if 'TEMİZ' not in seviye.upper():
            c.execute('''
                INSERT INTO tehditler (analiz_id, tarih, kategori, seviye, aciklama, aksiyon)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                analiz_id, tarih,
                t.get('kategori', ''),
                seviye,
                t.get('aciklama', ''),
                t.get('aksiyon', '')
            ))

    # TR: Günlük istatistiği güncelle
    # EN: Update daily statistics
    bugun = datetime.now().strftime('%Y-%m-%d')
    c.execute('SELECT id FROM istatistikler WHERE tarih = ?', (bugun,))
    row = c.fetchone()

    # TR: Sütun adını sabit listeden doğrula - SQL injection önlemi
    # EN: Validate column name from fixed list - SQL injection prevention
    VALID_COLUMNS = {'temiz', 'dusuk', 'orta', 'yuksek', 'kritik'}
    seviye_col = {
        'TEMİZ': 'temiz', 'DÜŞÜK': 'dusuk',
        'ORTA': 'orta', 'YÜKSEK': 'yuksek', 'KRİTİK': 'kritik'
    }.get(highest, 'temiz')

    # TR: Güvenlik kontrolü - geçersiz sütun adı ise varsayılana dön
    # EN: Safety check - fall back to default if invalid column name
    if seviye_col not in VALID_COLUMNS:
        seviye_col = 'temiz'

    if row:
        # TR: Sütun adı sabit listeden geldiği için f-string güvenli
        # EN: Column name comes from fixed list so f-string is safe here
        c.execute(f'''
            UPDATE istatistikler
            SET toplam_analiz = toplam_analiz + 1, {seviye_col} = {seviye_col} + 1
            WHERE tarih = ?
        ''', (bugun,))
    else:
        c.execute(f'''
            INSERT INTO istatistikler (tarih, toplam_analiz, {seviye_col})
            VALUES (?, 1, 1)
        ''', (bugun,))

    conn.commit()
    conn.close()

    print(f"Kaydedildi: {tarih} | Seviye: {highest} | "
          f"Tehdit sayısı: {len([t for t in threats if 'TEMİZ' not in t.get('seviye', 'TEMİZ').upper()])}")

if __name__ == '__main__':
    analysis_text = sys.stdin.read()
    log_boyutu = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    bildirim = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    save_analysis(analysis_text, log_boyutu, bildirim)