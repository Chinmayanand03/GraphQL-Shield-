import os
import sqlite3
import threading
from typing import Generator
from app.config import settings

# Every authorization decision does several small queries (owner lookups, audit
# rows, layer events). Opening and closing a SQLite connection for each one was
# about three quarters of a request's time, so idle connections are pooled per
# database file and handed out to one caller at a time.
_POOL_MAX_IDLE = 8
_pool: dict[str, list[sqlite3.Connection]] = {}
_pool_lock = threading.Lock()


class _PooledConnection(sqlite3.Connection):
    """close() returns the connection to the pool instead of closing it."""

    pool_key: str = ""

    def close(self):
        _release(self)


def _release(conn: _PooledConnection) -> None:
    try:
        # A caller that failed mid-transaction must not hand on a held lock.
        conn.rollback()
    except sqlite3.Error:
        sqlite3.Connection.close(conn)
        return
    with _pool_lock:
        idle = _pool.setdefault(conn.pool_key, [])
        if len(idle) < _POOL_MAX_IDLE and conn not in idle:
            idle.append(conn)
            return
    sqlite3.Connection.close(conn)


def close_pooled_connections(db_file: str | None = None) -> None:
    """Really close idle pooled connections (all, or one database file's), e.g.
    before deleting the file, which Windows refuses while it is open."""
    with _pool_lock:
        keys = [os.path.abspath(db_file)] if db_file else list(_pool)
        connections = [conn for key in keys for conn in _pool.pop(key, [])]
    for conn in connections:
        sqlite3.Connection.close(conn)


def _database_file() -> str:
    db_file = settings.DATABASE_URL.replace("sqlite:///", "")
    if not os.path.isabs(db_file) and not os.path.exists(db_file):
        root_db = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", db_file.lstrip("./\\")))
        if os.path.exists(root_db):
            db_file = root_db
    return os.path.abspath(db_file)


def get_db_connection():
    """
    Returns a connection to the SQLite database, reused from the pool when one
    is idle. Callers close() it as usual, which returns it to the pool.
    """
    db_file = _database_file()
    with _pool_lock:
        idle = _pool.get(db_file)
        if idle:
            return idle.pop()
    conn = sqlite3.connect(db_file, check_same_thread=False, factory=_PooledConnection)
    conn.pool_key = db_file
    conn.row_factory = sqlite3.Row
    # Enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON")
    # Every authorization decision is audited, so commits are frequent. With WAL
    # (set in init_db), NORMAL skips the disk sync on each commit; the database
    # stays consistent after a crash and loses at most the latest commits on
    # power loss.
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn

def init_db():
    """
    Initializes the database schemas.
    """
    conn = get_db_connection()
    # Write-ahead logging: readers do not block the audit writer, and commits are
    # cheap. The mode is stored in the database file.
    conn.execute("PRAGMA journal_mode = WAL")
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
            layer TEXT,
            prev_hash TEXT,
            row_hash TEXT
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

    _drop_audit_foreign_keys(cursor)

    # Tamper-evident hash chain (app/security/audit.py). Older rows keep NULL
    # hashes and are reported as legacy rows.
    audit_columns = {row[1] for row in cursor.execute("PRAGMA table_info(audit_logs)")}
    for column in ("prev_hash", "row_hash"):
        if column not in audit_columns:
            cursor.execute(f"ALTER TABLE audit_logs ADD COLUMN {column} TEXT")

    _upgrade_legacy_password_hashes(cursor)

    conn.commit()
    conn.close()


def _drop_audit_foreign_keys(cursor) -> None:
    """Older audit_logs tables tie object_id to objects(id) and user_id to
    users(id), but audited objects can be users or IDs that do not exist (a
    denied probe), and callers come from tokens, so inserts failed. The audit log
    must record every decision. SQLite cannot drop a constraint in place, so
    rebuild the table."""
    if not cursor.execute("PRAGMA foreign_key_list(audit_logs)").fetchall():
        return
    columns = "id, user_id, role, operation, object_type, object_id, path, decision, reason, risk_score, risk_level, timestamp, layer"
    cursor.execute("ALTER TABLE audit_logs RENAME TO audit_logs_old")
    cursor.execute('''
        CREATE TABLE audit_logs (
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
            layer TEXT
        )
    ''')
    cursor.execute(f"INSERT INTO audit_logs ({columns}) SELECT {columns} FROM audit_logs_old")
    cursor.execute("DROP TABLE audit_logs_old")


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
