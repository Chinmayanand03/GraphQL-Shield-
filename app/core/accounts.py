"""
Account protection: stops account takeover rather than only recording it.

- Sign-in lockout. Repeated wrong passwords lock the username, and many failures
  from one client address block that address, for a while. A locked or blocked
  sign-in is refused before the password is checked, and unknown usernames are
  locked exactly like real ones, so the replies do not reveal which accounts exist.
- Equal sign-in time. An unknown username is checked against a dummy hash, so it
  takes as long as a real one and timing does not reveal which accounts exist.
- Server-side sessions. Every token carries an ID and the account's session
  version. A request is accepted only if the account still exists, the token has
  not been revoked (logout), and the version still matches (logout everywhere,
  password change). The role comes from the database, never from the token.
- Password policy for new passwords, and a production check that refuses to start
  while any account still has its demo password.
"""
from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass

from app.config import settings
from app.core.passwords import hash_password, verify_password
from app.database import get_db_connection

logger = logging.getLogger(__name__)

# Verifying against this when the username is unknown makes both cases equally slow.
_DUMMY_HASH = hash_password(secrets.token_hex(16))

COMMON_PASSWORDS = frozenset({
    "password", "password1", "password123", "123456", "12345678", "123456789", "1234567890",
    "qwerty", "qwerty123", "letmein", "welcome", "welcome123", "admin", "admin123", "iloveyou",
    "abc123", "111111", "000000", "passw0rd", "changeme",
})


def init_account_tables(cursor) -> None:
    """Tables and columns for lockouts and server-side sessions (idempotent)."""
    columns = {row[1] for row in cursor.execute("PRAGMA table_info(users)")}
    if "token_version" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            key TEXT PRIMARY KEY,
            failures INTEGER NOT NULL,
            window_start REAL NOT NULL,
            locked_until REAL NOT NULL DEFAULT 0
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS revoked_tokens (
            jti TEXT PRIMARY KEY,
            expires_at REAL NOT NULL
        )
    """)


# ----------------------------------------------------------------- sign-in lockout

@dataclass
class LoginBlocked(Exception):
    retry_after: int


def _keys(username: str, client: str | None) -> list[tuple[str, int]]:
    keys = [(f"user:{username.strip().lower()}", settings.LOGIN_MAX_FAILURES)]
    if client:
        keys.append((f"ip:{client}", settings.LOGIN_IP_MAX_FAILURES))
    return keys


def check_not_locked(username: str, client: str | None) -> None:
    """Raise LoginBlocked while the username or the client address is locked."""
    now = time.time()
    conn = get_db_connection()
    try:
        for key, _ in _keys(username, client):
            row = conn.execute("SELECT locked_until FROM login_attempts WHERE key = ?", (key,)).fetchone()
            if row and row["locked_until"] > now:
                raise LoginBlocked(retry_after=int(row["locked_until"] - now) + 1)
    finally:
        conn.close()


def record_failure(username: str, client: str | None) -> None:
    """Count a failed sign-in; lock a key that reaches its limit within the window."""
    now = time.time()
    conn = get_db_connection()
    try:
        for key, limit in _keys(username, client):
            row = conn.execute("SELECT failures, window_start FROM login_attempts WHERE key = ?", (key,)).fetchone()
            if row is None or now - row["window_start"] > settings.LOGIN_WINDOW_SECONDS:
                failures, window_start = 1, now
            else:
                failures, window_start = row["failures"] + 1, row["window_start"]
            locked_until = now + settings.LOGIN_LOCK_SECONDS if failures >= limit else 0
            conn.execute(
                "INSERT INTO login_attempts (key, failures, window_start, locked_until) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET failures = excluded.failures, "
                "window_start = excluded.window_start, locked_until = excluded.locked_until",
                (key, 0 if locked_until else failures, now if locked_until else window_start, locked_until))
            if locked_until:
                logger.warning("Sign-in locked for %s after %d failures", key, failures)
        conn.commit()
    finally:
        conn.close()


def record_success(username: str) -> None:
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM login_attempts WHERE key = ?", (f"user:{username.strip().lower()}",))
        conn.commit()
    finally:
        conn.close()


def authenticate(username: str, password: str) -> dict | None:
    """The account for a correct username and password, or None. Takes the same time
    whether or not the username exists."""
    conn = get_db_connection()
    try:
        user = conn.execute("SELECT id, username, role, password_hash FROM users WHERE username = ?",
                            (username.strip().lower(),)).fetchone()
    finally:
        conn.close()
    if user is None:
        verify_password(password, _DUMMY_HASH)
        return None
    return dict(user) if verify_password(password, user["password_hash"]) else None


# ---------------------------------------------------------------- server-side sessions

class SessionInvalid(Exception):
    pass


def token_version(user_id) -> int:
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT token_version FROM users WHERE id = ?", (user_id,)).fetchone()
    except Exception:
        return 0
    finally:
        conn.close()
    return row["token_version"] if row else 0


def validate_session(claims: dict) -> dict:
    """Claims for a request whose token passed its signature check, with the role taken
    from the database. Raises SessionInvalid when the session no longer stands."""
    conn = get_db_connection()
    try:
        user = conn.execute("SELECT role, token_version FROM users WHERE id = ?", (claims.get("user_id"),)).fetchone()
        if user is None:
            raise SessionInvalid("account no longer exists")
        if claims.get("ver", 0) != user["token_version"]:
            raise SessionInvalid("session ended")
        jti = claims.get("jti")
        if jti and conn.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,)).fetchone():
            raise SessionInvalid("token revoked")
    finally:
        conn.close()
    return {**claims, "role": user["role"]}


def revoke_token(claims: dict) -> None:
    """Log out one session: its token stops working before it expires."""
    jti = claims.get("jti")
    if not jti:
        return
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (time.time(),))
        conn.execute("INSERT OR IGNORE INTO revoked_tokens (jti, expires_at) VALUES (?, ?)",
                     (jti, float(claims.get("exp", time.time() + 86400))))
        conn.commit()
    finally:
        conn.close()


def end_all_sessions(user_id) -> None:
    """Log out everywhere: every token issued so far for this account stops working."""
    conn = get_db_connection()
    try:
        conn.execute("UPDATE users SET token_version = token_version + 1 WHERE id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()


# ----------------------------------------------------------------------- passwords

def password_problems(password: str, username: str) -> list[str]:
    """Reasons a new password is too weak; empty when it is acceptable."""
    problems = []
    if len(password) < 12:
        problems.append("use at least 12 characters")
    lowered = password.lower()
    if username and username.lower() in lowered:
        problems.append("do not include your username")
    if lowered in COMMON_PASSWORDS or lowered.rstrip("0123456789!") in COMMON_PASSWORDS:
        problems.append("choose a less common password")
    if len(set(password)) < 5:
        problems.append("use more different characters")
    return problems


def change_password(user_id, current_password: str, new_password: str) -> list[str]:
    """Change a password after checking the current one. Ends every session of the
    account, including other devices. Returns the problems, empty on success."""
    conn = get_db_connection()
    try:
        user = conn.execute("SELECT username, password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None or not verify_password(current_password, user["password_hash"]):
            return ["current password is wrong"]
        problems = password_problems(new_password, user["username"])
        if verify_password(new_password, user["password_hash"]):
            problems.append("choose a password you have not used here")
        if problems:
            return problems
        conn.execute("UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE id = ?",
                     (hash_password(new_password), user_id))
        conn.commit()
        return []
    finally:
        conn.close()


def accounts_with_demo_passwords() -> list[str]:
    """Usernames whose password is still the demo pattern <username>123."""
    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT username, password_hash FROM users").fetchall()
    finally:
        conn.close()
    return [row["username"] for row in rows if verify_password(f"{row['username']}123", row["password_hash"])]


def check_production_accounts() -> None:
    """Refuse to run in production while an account still has its demo password."""
    if settings.ENVIRONMENT.lower() != "production":
        return
    weak = accounts_with_demo_passwords()
    if weak:
        raise RuntimeError(f"Accounts still use demo passwords: {', '.join(weak)}. Change them before production.")
