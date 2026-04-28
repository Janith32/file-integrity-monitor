import hashlib
import sqlite3
import os
import time
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

DB_PATH = "fim.db"
MONITOR_PATH = r"D:\FIM_Project123\Web_Server_Files"

def hash_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def init_alerts_table():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        event_type TEXT,
        file_path TEXT,
        old_hash TEXT,
        new_hash TEXT,
        mitre_technique TEXT,
        severity TEXT
    )''')
    conn.commit()
    conn.close()

def log_alert(event_type, file_path, old_hash="", new_hash="", mitre="", severity="MEDIUM"):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO alerts (timestamp, event_type, file_path, old_hash, new_hash, mitre_technique, severity) VALUES (?, ?, ?, ?, ?, ?, ?)",
              (timestamp, event_type, file_path, old_hash, new_hash, mitre, severity))
    conn.commit()
    conn.close()
    print(f"[{timestamp}] [{severity}] {event_type}: {file_path}")

def get_baseline(path):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT hash, size, mtime FROM baseline WHERE path = ?", (path,))
    row = c.fetchone()
    conn.close()
    return row

def check_file(path):
    if not os.path.exists(path):
        log_alert("DELETED", path, mitre="T1070.004", severity="HIGH")
        return
    
    baseline = get_baseline(path)
    if baseline is None:
        log_alert("NEW_FILE", path, mitre="T1105", severity="MEDIUM")
        return
    
    old_hash, old_size, old_mtime = baseline
    
    try:
        stat = os.stat(path)
        if stat.st_size == old_size and stat.st_mtime == old_mtime:
            return
    except Exception:
        return
    
    try:
        new_hash = hash_file(path)
        if new_hash != old_hash:
            log_alert("MODIFIED", path, old_hash=old_hash, new_hash=new_hash, mitre="T1565.001", severity="HIGH")
    except Exception as e:
        print(f"Error hashing {path}: {e}")

class FIMHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_event = {}
    
    def should_process(self, path):
        now = time.time()
        if path in self.last_event and now - self.last_event[path] < 1.0:
            return False
        self.last_event[path] = now
        return True
    
    def on_modified(self, event):
        if event.is_directory or not self.should_process(event.src_path):
            return
        time.sleep(0.5)
        check_file(event.src_path)
    
    def on_created(self, event):
        if event.is_directory or not self.should_process(event.src_path):
            return
        check_file(event.src_path)
    
    def on_deleted(self, event):
        if event.is_directory:
            return
        log_alert("DELETED", event.src_path, mitre="T1070.004", severity="HIGH")

if __name__ == "__main__":
    init_alerts_table()
    print(f"Monitoring: {MONITOR_PATH}")
    print("Press Ctrl+C to stop\n")
    
    observer = Observer()
    observer.schedule(FIMHandler(), MONITOR_PATH, recursive=True)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\nMonitoring stopped.")
    observer.join()