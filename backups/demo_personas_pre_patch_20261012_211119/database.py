import sqlite3
from typing import Generator
from app.config import settings

def get_db_connection():
    """
    Creates and returns a connection to the SQLite database.
    """
    db_file = settings.DATABASE_URL.replace("sqlite:///", "")
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
    
    conn.commit()
    conn.close()

def get_db() -> Generator[sqlite3.Connection, None, None]:
    """
    FastAPI dependency that provides a database connection per request.
    """
    conn = get_db_connection()
    try:
        yield conn
    finally:
        conn.close()
