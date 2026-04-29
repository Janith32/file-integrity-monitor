import sqlite3
import bcrypt
from datetime import datetime

DB_PATH = "fim.db"

def init_users_table():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_login TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        username TEXT,
        action TEXT NOT NULL,
        details TEXT,
        success INTEGER
    )''')
    conn.commit()
    conn.close()

def hash_password(password):
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password, password_hash):
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def create_user(username, password, role):
    if role not in ['admin', 'analyst']:
        return False, "Invalid role"
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        password_hash = hash_password(password)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                  (username, password_hash, role, timestamp))
        conn.commit()
        log_audit(username, "USER_CREATED", f"Role: {role}", success=1)
        return True, "User created successfully"
    except sqlite3.IntegrityError:
        return False, "Username already exists"
    finally:
        conn.close()

def authenticate(username, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash, role FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    
    if row is None:
        log_audit(username, "LOGIN_FAILED", "User does not exist", success=0)
        conn.close()
        return False, None
    
    password_hash, role = row
    if verify_password(password, password_hash):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("UPDATE users SET last_login = ? WHERE username = ?", (timestamp, username))
        conn.commit()
        log_audit(username, "LOGIN_SUCCESS", f"Role: {role}", success=1)
        conn.close()
        return True, role
    else:
        log_audit(username, "LOGIN_FAILED", "Wrong password", success=0)
        conn.close()
        return False, None

def log_audit(username, action, details="", success=1):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO audit_log (timestamp, username, action, details, success) VALUES (?, ?, ?, ?, ?)",
              (timestamp, username, action, details, success))
    conn.commit()
    conn.close()

def get_all_users():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, username, role, created_at, last_login FROM users ORDER BY id")
    users = c.fetchall()
    conn.close()
    return users

def delete_user(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    log_audit(username, "USER_DELETED", success=1)

def init_default_admin():
    """Create a default admin if no users exist."""
    init_users_table()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users")
    count = c.fetchone()[0]
    conn.close()
    
    if count == 0:
        success, msg = create_user("admin", "admin123", "admin")
        if success:
            print("Default admin created. Username: admin, Password: admin123")
            print("CHANGE THIS PASSWORD AFTER FIRST LOGIN!")

if __name__ == "__main__":
    init_default_admin()