import hashlib
import sqlite3
import os
import time
import shutil
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ===== CONFIGURATION =====
DB_PATH = "fim.db"
MONITOR_PATH = r"D:\FIM_Project123\Web_Server_Files"
BACKUP_PATH = r"D:\FIM_Project123\Backup"

# Email config - REPLACE THESE
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_FROM = "dilshanfernado061@gmail.com"
EMAIL_PASSWORD = "ciey opcs dbns tszx"  # 16-char app password, no spaces
EMAIL_TO = "danithfernando63@gmail.com"  # can be same as FROM

AUTO_RESTORE = True
EMAIL_ENABLED = True

# Self-trigger prevention
pending_restores = set()

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
        severity TEXT,
        action_taken TEXT
    )''')
    conn.commit()
    conn.close()

def create_backup(folder):
    """Create initial backup of all monitored files."""
    Path(BACKUP_PATH).mkdir(parents=True, exist_ok=True)
    count = 0
    for root, dirs, files in os.walk(folder):
        for filename in files:
            src = os.path.join(root, filename)
            rel = os.path.relpath(src, folder)
            dst = os.path.join(BACKUP_PATH, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            count += 1
    print(f"Backup created: {count} files in {BACKUP_PATH}")

def restore_file(path):
    """Restore a file from backup."""
    rel = os.path.relpath(path, MONITOR_PATH)
    backup_file = os.path.join(BACKUP_PATH, rel)
    if os.path.exists(backup_file):
        pending_restores.add(path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        shutil.copy2(backup_file, path)
        print(f"  -> RESTORED from backup")
        return True
    else:
        print(f"  -> No backup available for restore")
        return False

def send_email_alert(event_type, file_path, severity, mitre):
    if not EMAIL_ENABLED:
        return
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_FROM
        msg['To'] = EMAIL_TO
        msg['Subject'] = f"[FIM ALERT - {severity}] {event_type}: {os.path.basename(file_path)}"
        body = f"""
File Integrity Monitor Alert
============================

Event Type: {event_type}
Severity: {severity}
File Path: {file_path}
MITRE ATT&CK: {mitre}
Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

This is an automated alert from your FIM system.
Dashboard: http://localhost:8501
"""
        msg.attach(MIMEText(body, 'plain'))
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_FROM, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"  -> Email sent to {EMAIL_TO}")
    except Exception as e:
        print(f"  -> Email failed: {e}")

def log_alert(event_type, file_path, old_hash="", new_hash="", mitre="", severity="MEDIUM", action=""):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO alerts (timestamp, event_type, file_path, old_hash, new_hash, mitre_technique, severity, action_taken) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
              (timestamp, event_type, file_path, old_hash, new_hash, mitre, severity, action))
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
    if path in pending_restores:
        pending_restores.discard(path)
        return  # Ignore self-triggered restore events
    
    if not os.path.exists(path):
        action = ""
        if AUTO_RESTORE and restore_file(path):
            action = "Auto-restored from backup"
        log_alert("DELETED", path, mitre="T1070.004", severity="HIGH", action=action)
        send_email_alert("DELETED", path, "HIGH", "T1070.004")
        return
    
    baseline = get_baseline(path)
    if baseline is None:
        log_alert("NEW_FILE", path, mitre="T1105", severity="MEDIUM")
        send_email_alert("NEW_FILE", path, "MEDIUM", "T1105")
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
            action = ""
            if AUTO_RESTORE and restore_file(path):
                action = "Auto-restored from backup"
            log_alert("MODIFIED", path, old_hash=old_hash, new_hash=new_hash, mitre="T1565.001", severity="HIGH", action=action)
            send_email_alert("MODIFIED", path, "HIGH", "T1565.001")
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
        if event.is_directory or event.src_path in pending_restores:
            return
        check_file(event.src_path)

if __name__ == "__main__":
    init_alerts_table()
    create_backup(MONITOR_PATH)
    print(f"\nMonitoring: {MONITOR_PATH}")
    print(f"Backup: {BACKUP_PATH}")
    print(f"Auto-restore: {AUTO_RESTORE}")
    print(f"Email alerts: {EMAIL_ENABLED}")
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