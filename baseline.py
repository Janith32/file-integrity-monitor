import hashlib
import sqlite3
import os
from pathlib import Path

DB_PATH = "fim.db"
MONITOR_PATH = r"D:\FIM_Project123\Web_Server_Files"

def hash_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS baseline (
        path TEXT PRIMARY KEY,
        hash TEXT,
        size INTEGER,
        mtime REAL
    )''')
    conn.commit()
    conn.close()

def create_baseline(folder):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    count = 0
    for root, dirs, files in os.walk(folder):
        for filename in files:
            path = os.path.join(root, filename)
            try:
                file_hash = hash_file(path)
                stat = os.stat(path)
                c.execute("INSERT OR REPLACE INTO baseline VALUES (?, ?, ?, ?)",
                          (path, file_hash, stat.st_size, stat.st_mtime))
                count += 1
                print(f"Hashed: {path}")
            except Exception as e:
                print(f"Error hashing {path}: {e}")
    conn.commit()
    conn.close()
    print(f"\nBaseline created: {count} files")

if __name__ == "__main__":
    Path(MONITOR_PATH).mkdir(parents=True, exist_ok=True)
    create_baseline(MONITOR_PATH)