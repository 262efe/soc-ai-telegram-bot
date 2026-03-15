import sqlite3
import os
import stat

from soc_config import load_soc_config

config = load_soc_config()
DB_PATH = config.get("DB_PATH", "/var/lib/soc/soc_logs.db")
os.makedirs("/var/lib/soc", exist_ok=True)

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

# TR: Analiz sonuçları tablosu
# EN: Analysis results table
c.execute('''
CREATE TABLE IF NOT EXISTS analizler (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tarih TEXT NOT NULL,
    ozet TEXT,
    ham_analiz TEXT,
    en_yuksek_seviye TEXT DEFAULT 'TEMİZ',
    bildirim_gonderildi INTEGER DEFAULT 0,
    log_boyutu INTEGER
)
''')

# TR: Tespit edilen tehditler tablosu
# EN: Detected threats table
c.execute('''
CREATE TABLE IF NOT EXISTS tehditler (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analiz_id INTEGER,
    tarih TEXT NOT NULL,
    kategori TEXT,
    seviye TEXT,
    aciklama TEXT,
    aksiyon TEXT,
    FOREIGN KEY (analiz_id) REFERENCES analizler(id)
)
''')

# TR: İstatistik tablosu
# EN: Statistics table
c.execute('''
CREATE TABLE IF NOT EXISTS istatistikler (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tarih TEXT NOT NULL,
    toplam_analiz INTEGER DEFAULT 0,
    temiz INTEGER DEFAULT 0,
    dusuk INTEGER DEFAULT 0,
    orta INTEGER DEFAULT 0,
    yuksek INTEGER DEFAULT 0,
    kritik INTEGER DEFAULT 0
)
''')

# TR: Ban geçmişi tablosu
# EN: Ban history table
c.execute('''
CREATE TABLE IF NOT EXISTS ban_gecmisi (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tarih TEXT NOT NULL,
    ip TEXT,
    sebep TEXT,
    kural_id TEXT,
    otomatik INTEGER DEFAULT 1,
    ban_bitis TEXT
)
''')

conn.commit()
conn.close()

# TR: Veritabanı dosya izinlerini kısıtla (0600)
# EN: Restrict database file permissions (0600)
try:
    os.chmod(DB_PATH, stat.S_IRUSR | stat.S_IWUSR)
except Exception as e:
    print(f"Izin guncelleme hatasi: {e}")

print("Veritabanı başarıyla oluşturuldu ve yapılandırıldı:", DB_PATH)
