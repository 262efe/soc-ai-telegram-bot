import sqlite3
import os
import stat

from soc_config import load_soc_config

config = load_soc_config()
DB_PATH = config.get("DB_PATH", "/var/lib/soc/soc_logs.db")
os.makedirs("/var/lib/soc", exist_ok=True)

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

# Analysis results table
c.execute('''
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    summary TEXT,
    raw_analysis TEXT,
    max_severity TEXT DEFAULT 'CLEAN',
    notification_sent INTEGER DEFAULT 0,
    log_size INTEGER
)
''')

# Detected threats table
c.execute('''
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER,
    timestamp TEXT NOT NULL,
    category TEXT,
    severity TEXT,
    description TEXT,
    action TEXT,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id)
)
''')

# Statistics table
c.execute('''
CREATE TABLE IF NOT EXISTS statistics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    total_analyses INTEGER DEFAULT 0,
    clean INTEGER DEFAULT 0,
    low INTEGER DEFAULT 0,
    medium INTEGER DEFAULT 0,
    high INTEGER DEFAULT 0,
    critical INTEGER DEFAULT 0
)
''')

# Ban log table
c.execute('''
CREATE TABLE IF NOT EXISTS ban_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    ip TEXT,
    reason TEXT,
    rule_id TEXT,
    automatic INTEGER DEFAULT 1,
    expiry TEXT
)
''')

# Command history table
c.execute('''
CREATE TABLE IF NOT EXISTS command_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    command TEXT,
    reason TEXT,
    result TEXT,
    approved_by TEXT
)
''')

# Pending commands table
c.execute('''
CREATE TABLE IF NOT EXISTS pending_commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    command TEXT,
    reason TEXT,
    message_id INTEGER,
    chat_id TEXT,
    status TEXT DEFAULT 'pending'
)
''')

# Rule detections table
c.execute('''
CREATE TABLE IF NOT EXISTS rule_detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    rule_id TEXT,
    rule_name TEXT,
    severity TEXT,
    description TEXT,
    match_count INTEGER,
    action TEXT
)
''')

# Create indexes for performance optimization
c.execute('CREATE INDEX IF NOT EXISTS idx_analyses_timestamp ON analyses (timestamp)')
c.execute('CREATE INDEX IF NOT EXISTS idx_threats_analysis_id ON threats (analysis_id)')
c.execute('CREATE INDEX IF NOT EXISTS idx_threats_category ON threats (category)')
c.execute('CREATE INDEX IF NOT EXISTS idx_statistics_timestamp ON statistics (timestamp)')
c.execute('CREATE INDEX IF NOT EXISTS idx_ban_log_ip ON ban_log (ip)')
c.execute('CREATE INDEX IF NOT EXISTS idx_rule_detections_timestamp ON rule_detections (timestamp)')
c.execute('CREATE INDEX IF NOT EXISTS idx_rule_detections_rule_id ON rule_detections (rule_id)')

conn.commit()
conn.close()

# Restrict database file permissions (0600)
try:
    os.chmod(DB_PATH, stat.S_IRUSR | stat.S_IWUSR)
except Exception as e:
    print(f"Permission update error: {e}")

print("Database successfully created and configured:", DB_PATH)
