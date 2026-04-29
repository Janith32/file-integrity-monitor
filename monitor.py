import hashlib
import sqlite3
import os
import time
import shutil
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ===== CONFIGURATION =====
DB_PATH = "fim.db"
BACKUP_PATH = r"D:\FIM_Project123\Backup"
RELOAD_INTERVAL = 10  # seconds - how often to check for new paths/rules
AUTO_RESTORE = True

# Self-trigger prevention for auto-restore
pending_restores = set()


# ===== HASHING =====
def hash_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


# ===== DATABASE TABLES =====
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


# ===== READ CONFIG FROM DATABASE =====
def get_active_paths():
    """Read enabled monitored paths from the database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT path FROM monitored_paths WHERE enabled = 1")
        paths = [row[0] for row in c.fetchall()]
    except sqlite3.OperationalError:
        paths = []
    conn.close()
    return paths


def get_active_rules():
    """Read enabled severity rules from the database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT pattern, severity FROM severity_rules WHERE enabled = 1")
        rules = c.fetchall()
    except sqlite3.OperationalError:
        rules = []
    conn.close()
    return rules


def classify_severity(file_path, default_severity):
    """Apply user-defined rules to determine severity. Falls back to default if no rule matches."""
    rules = get_active_rules()
    for pattern, severity in rules:
        if pattern.lower() in file_path.lower():
            return severity
    return default_severity


# ===== BACKUP =====
def create_backup_for_path(folder):
    """Create backup snapshot of all files in a monitored folder."""
    Path(BACKUP_PATH).mkdir(parents=True, exist_ok=True)
    count = 0
    for root, dirs, files in os.walk(folder):
        for filename in files:
            src = os.path.join(root, filename)
            try:
                rel = os.path.relpath(src, folder)
                folder_name = os.path.basename(folder.rstrip("\\/"))
                dst = os.path.join(BACKUP_PATH, folder_name, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src, dst)
                count += 1
            except Exception as e:
                print(f"Backup error for {src}: {e}")
    print(f"  Backed up {count} files from {folder}")


def restore_file(path, monitor_folder):
    """Restore a file from backup."""
    folder_name = os.path.basename(monitor_folder.rstrip("\\/"))
    rel = os.path.relpath(path, monitor_folder)
    backup_file = os.path.join(BACKUP_PATH, folder_name, rel)
    if os.path.exists(backup_file):
        pending_restores.add(path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        shutil.copy2(backup_file, path)
        print(f"  -> RESTORED from backup")
        return True
    print(f"  -> No backup available for {path}")
    return False


# ===== ALERT LOGGING =====
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


def add_to_baseline(path):
    """Add a file to baseline (used when new paths are added)."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS baseline (
        path TEXT PRIMARY KEY,
        hash TEXT, size INTEGER, mtime REAL
    )''')
    try:
        file_hash = hash_file(path)
        stat = os.stat(path)
        c.execute("INSERT OR REPLACE INTO baseline VALUES (?, ?, ?, ?)",
                  (path, file_hash, stat.st_size, stat.st_mtime))
        conn.commit()
    except Exception as e:
        print(f"Baseline error for {path}: {e}")
    conn.close()


def baseline_folder(folder):
    """Add all files in a folder to baseline."""
    for root, dirs, files in os.walk(folder):
        for filename in files:
            add_to_baseline(os.path.join(root, filename))


# ===== EVENT HANDLER =====
class FIMHandler(FileSystemEventHandler):
    def __init__(self, monitor_folder):
        self.monitor_folder = monitor_folder
        self.last_event = {}
    
    def should_process(self, path):
        now = time.time()
        if path in self.last_event and now - self.last_event[path] < 1.0:
            return False
        self.last_event[path] = now
        return True
    
    def check_file(self, path):
        if path in pending_restores:
            pending_restores.discard(path)
            return
        
        if not os.path.exists(path):
            severity = classify_severity(path, "HIGH")
            action = ""
            if AUTO_RESTORE and restore_file(path, self.monitor_folder):
                action = "Auto-restored from backup"
            log_alert("DELETED", path, mitre="T1070.004", severity=severity, action=action)
            return
        
        baseline = get_baseline(path)
        if baseline is None:
            severity = classify_severity(path, "MEDIUM")
            log_alert("NEW_FILE", path, mitre="T1105", severity=severity)
            add_to_baseline(path)  # auto-add new files to baseline
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
                severity = classify_severity(path, "HIGH")
                action = ""
                if AUTO_RESTORE and restore_file(path, self.monitor_folder):
                    action = "Auto-restored from backup"
                log_alert("MODIFIED", path, old_hash=old_hash, new_hash=new_hash,
                          mitre="T1565.001", severity=severity, action=action)
        except Exception as e:
            print(f"Error hashing {path}: {e}")
    
    def on_modified(self, event):
        if event.is_directory or not self.should_process(event.src_path):
            return
        time.sleep(0.5)
        self.check_file(event.src_path)
    
    def on_created(self, event):
        if event.is_directory or not self.should_process(event.src_path):
            return
        self.check_file(event.src_path)
    
    def on_deleted(self, event):
        if event.is_directory or event.src_path in pending_restores:
            return
        self.check_file(event.src_path)


# ===== DYNAMIC OBSERVER MANAGEMENT =====
class DynamicMonitor:
    def __init__(self):
        self.observers = {}  # path -> Observer instance
    
    def start_path(self, path):
        if path in self.observers:
            return
        if not os.path.exists(path):
            print(f"  ! Path does not exist: {path}")
            return
        
        print(f"  + Starting monitor for: {path}")
        # Create baseline and backup for new path
        baseline_folder(path)
        create_backup_for_path(path)
        
        observer = Observer()
        handler = FIMHandler(path)
        observer.schedule(handler, path, recursive=True)
        observer.start()
        self.observers[path] = observer
    
    def stop_path(self, path):
        if path in self.observers:
            print(f"  - Stopping monitor for: {path}")
            self.observers[path].stop()
            self.observers[path].join()
            del self.observers[path]
    
    def reconcile(self):
        """Compare desired paths (from DB) with active paths and adjust."""
        desired = set(get_active_paths())
        active = set(self.observers.keys())
        
        # Start new paths
        for path in desired - active:
            self.start_path(path)
        
        # Stop removed paths
        for path in active - desired:
            self.stop_path(path)
    
    def stop_all(self):
        for path in list(self.observers.keys()):
            self.stop_path(path)


# ===== MAIN =====
if __name__ == "__main__":
    init_alerts_table()
    
    print("=" * 60)
    print("FIM System Starting")
    print("=" * 60)
    print(f"Database: {DB_PATH}")
    print(f"Backup folder: {BACKUP_PATH}")
    print(f"Auto-restore: {AUTO_RESTORE}")
    print(f"Reload interval: {RELOAD_INTERVAL}s")
    print(f"Configure paths via the dashboard.")
    print("=" * 60)
    
    monitor = DynamicMonitor()
    
    try:
        while True:
            monitor.reconcile()
            if not monitor.observers:
                print("No paths configured. Add paths via the dashboard.")
            time.sleep(RELOAD_INTERVAL)
    except KeyboardInterrupt:
        print("\nStopping all monitors...")
        monitor.stop_all()
        print("Done.")