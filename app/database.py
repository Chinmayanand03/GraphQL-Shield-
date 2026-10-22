import os
import sqlite3
from typing import Generator
from app.config import settings

def get_db_connection():
    """
    Creates and returns a connection to the SQLite database.
    """
    db_file = settings.DATABASE_URL.replace("sqlite:///", "")
    if not os.path.isabs(db_file) and not os.path.exists(db_file):
        root_db = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", db_file.lstrip("./\\")))
        if os.path.exists(root_db):
            db_file = root_db
    conn = sqlite3.connect(db_file, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    """
    Initializes the database schemas.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            display_name TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # objects table (resources)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS objects (
            id INTEGER PRIMARY KEY,
            object_type TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            parent_id INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(owner_id) REFERENCES users(id),
            FOREIGN KEY(parent_id) REFERENCES objects(id)
        )
    ''')
    
    # audit_logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            role TEXT,
            operation TEXT,
            object_type TEXT,
            object_id INTEGER,
            path TEXT,
            decision TEXT,
            reason TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(object_id) REFERENCES objects(id)
        )
    ''')
    
    # layer_events table: what each defense layer did, including the cases where
    # Layer 2 caught an object that Layer 1 never evaluated (a Layer 1 blind spot).
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS layer_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            layer TEXT NOT NULL,
            event TEXT NOT NULL,
            object_type TEXT,
            object_id INTEGER,
            path TEXT,
            detail TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Older databases lack the column recording which layer wrote an audit row.
    audit_columns = {row[1] for row in cursor.execute("PRAGMA table_info(audit_logs)")}
    if "layer" not in audit_columns:
        cursor.execute("ALTER TABLE audit_logs ADD COLUMN layer TEXT")

    _upgrade_legacy_password_hashes(cursor)

    conn.commit()
    conn.close()


def _upgrade_legacy_password_hashes(cursor) -> None:
    """Replace legacy "hash_<password>" values with real PBKDF2 hashes."""
    from app.core.passwords import LEGACY_PREFIX, hash_password, is_legacy_hash

    rows = cursor.execute("SELECT id, password_hash FROM users").fetchall()
    for row in rows:
        if is_legacy_hash(row[1]):
            plain = row[1][len(LEGACY_PREFIX):]
            cursor.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (hash_password(plain), row[0]),
            )

def get_db() -> Generator[sqlite3.Connection, None, None]:
    """
    FastAPI dependency that provides a database connection per request.
    """
    conn = get_db_connection()
    try:
        yield conn
    finally:
        conn.close()
