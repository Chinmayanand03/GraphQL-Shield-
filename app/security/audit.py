"""
Audit log with a tamper-evident hash chain.

Every row stores the hash of the row before it (`prev_hash`) and its own hash
(`row_hash`) over its contents plus `prev_hash`. Editing or deleting any row
changes a hash that a later row depends on, so `verify_audit_chain` reports the
first broken link. Rows written before the chain existed carry no hash and are
reported as legacy rows.

This detects tampering by anyone who cannot rewrite every later hash; it is not
a defence against an attacker with full write access to the database file.
"""
import hashlib
import json
from datetime import datetime, timezone

from app.database import get_db_connection

CHAIN_FIELDS = ("user_id", "role", "operation", "object_type", "object_id", "path",
                "decision", "reason", "risk_score", "risk_level", "layer", "timestamp")


INTEGER_FIELDS = ("user_id", "object_id", "risk_score")


def _as_stored(value):
    """The value as SQLite's INTEGER affinity stores it (numeric text becomes an
    int), so the hash computed at write time matches the row read back later."""
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return value
    return value


def _row_hash(prev_hash: str | None, row: dict) -> str:
    payload = json.dumps({"prev": prev_hash, **{field: row.get(field) for field in CHAIN_FIELDS}},
                         sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log_decision(user_id: int, role: str, operation: str, object_type: str, object_id: int, path: str, decision: str, reason: str, risk_score: int, risk_level: str, layer: str | None = None):
    """
    Writes the full security context, decision, and risk metrics to the audit log.
    `layer` records which enforcement layer ("L1" or "L2") made the decision.
    """
    row = {
        "user_id": user_id, "role": role, "operation": operation, "object_type": object_type,
        "object_id": object_id, "path": path, "decision": decision, "reason": reason,
        "risk_score": risk_score, "risk_level": risk_level, "layer": layer,
        # Same format SQLite's CURRENT_TIMESTAMP uses (UTC).
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    }
    for field in INTEGER_FIELDS:
        row[field] = _as_stored(row[field])
    conn = get_db_connection()
    try:
        # IMMEDIATE takes the write lock first, so two writers cannot chain to the same row.
        conn.execute("BEGIN IMMEDIATE")
        last = conn.execute(
            "SELECT row_hash FROM audit_logs WHERE row_hash IS NOT NULL ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = last[0] if last else None
        conn.execute('''
            INSERT INTO audit_logs (user_id, role, operation, object_type, object_id, path, decision, reason, risk_score, risk_level, layer, timestamp, prev_hash, row_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (*(row[field] for field in CHAIN_FIELDS), prev_hash, _row_hash(prev_hash, row)))
        conn.commit()
    finally:
        # A failed insert must not leave a transaction holding the database lock.
        conn.close()


def verify_audit_chain(conn=None) -> dict:
    """Recompute every hashed row and its link to the previous one."""
    own = conn is None
    conn = conn or get_db_connection()
    try:
        legacy = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE row_hash IS NULL").fetchone()[0]
        rows = conn.execute(
            f"SELECT id, prev_hash, row_hash, {', '.join(CHAIN_FIELDS)} FROM audit_logs "
            "WHERE row_hash IS NOT NULL ORDER BY id"
        ).fetchall()
        expected_prev = None
        for checked, row in enumerate(rows):
            data = dict(row)
            if data["prev_hash"] != expected_prev or _row_hash(data["prev_hash"], data) != data["row_hash"]:
                return {"intact": False, "checked": checked, "first_broken_id": data["id"], "legacy_rows": legacy}
            expected_prev = data["row_hash"]
        return {"intact": True, "checked": len(rows), "first_broken_id": None, "legacy_rows": legacy}
    finally:
        if own:
            conn.close()
