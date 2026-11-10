from app.database import get_db_connection

def log_decision(user_id: int, role: str, operation: str, object_type: str, object_id: int, path: str, decision: str, reason: str, risk_score: int, risk_level: str):
    """
    Writes the full security context, decision, and risk metrics to the audit log.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO audit_logs (user_id, role, operation, object_type, object_id, path, decision, reason, risk_score, risk_level)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, role, operation, object_type, object_id, path, decision, reason, risk_score, risk_level))
    
    conn.commit()
    conn.close()
