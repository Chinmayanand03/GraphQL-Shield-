from app.database import get_db_connection

def log_decision(user_id: int, role: str, operation: str, object_type: str, object_id: int, path: str, decision: str, reason: str, risk_score: int, risk_level: str, layer: str | None = None):
    """
    Writes the full security context, decision, and risk metrics to the audit log.
    `layer` records which enforcement layer ("L1" or "L2") made the decision.
    """
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO audit_logs (user_id, role, operation, object_type, object_id, path, decision, reason, risk_score, risk_level, layer)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, role, operation, object_type, object_id, path, decision, reason, risk_score, risk_level, layer))
        conn.commit()
    finally:
        # A failed insert must not leave a transaction holding the database lock.
        conn.close()
