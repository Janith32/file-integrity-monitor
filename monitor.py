import hashlib
import sqlite3
import os
import time
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

def get_baseline(path):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT hash, size, mtime FROM baseline WHERE path = ?", (path,))
    row = c.fetchone()
    conn.close()
    return row

def check_file(path):
    if not os.path.exists(path):
        print(f"[ALERT] File DELETED: {path}")
        return
    
    baseline = get_baseline(path)
    if baseline is None:
        print(f"[ALERT] NEW FILE detected: {path}")
        return
    
    old_hash, old_size, old_mtime = baseline
    
    # Metadata-first check (your differentiator)
    try:
        stat = os.stat(path)
        if stat.st_size == old_size and stat.st_mtime == old_mtime:
            return  # No change, skip expensive hash
    except Exception:
        return
    
    # Metadata changed - now do expensive hash check
    try:
        new_hash = hash_file(path)
        if new_hash != old_hash:
            print(f"[ALERT] FILE MODIFIED: {path}")
            print(f"  Old hash: {old_hash[:16]}...")
            print(f"  New hash: {new_hash[:16]}...")
        else:
            print(f"[INFO] Metadata changed but hash same: {path}")
    except Exception as e:
        print(f"Error hashing {path}: {e}")

class FIMHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_event = {}  # For debouncing
    
    def should_process(self, path):
        # Debounce: ignore events within 1 second of last event for same file
        now = time.time()
        if path in self.last_event and now - self.last_event[path] < 1.0:
            return False
        self.last_event[path] = now
        return True
    
    def on_modified(self, event):
        if event.is_directory or not self.should_process(event.src_path):
            return
        # Small delay to let file finish writing
        time.sleep(0.5)
        check_file(event.src_path)
    
    def on_created(self, event):
        if event.is_directory or not self.should_process(event.src_path):
            return
        check_file(event.src_path)
    
    def on_deleted(self, event):
        if event.is_directory:
            return
        print(f"[ALERT] FILE DELETED: {event.src_path}")

if __name__ == "__main__":
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