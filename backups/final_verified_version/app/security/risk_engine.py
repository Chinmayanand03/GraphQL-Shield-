from app.database import get_db_connection

def calculate_risk(context, decision_reason: str) -> tuple[int, str]:
    """
    Calculates a deterministic BOLA risk score (0-100) based on the context 
    and the base authorization result.
    
    Returns (score, risk_level_string).
    """
    score = 0
    
    # Rule 1: Ownership Mismatch (Major Indicator)
    if decision_reason in ["OWNERSHIP_MISMATCH", "NESTED_AUTHORIZATION_VIOLATION"]:
        score += 80
        
    # Rule 2: Suspicious Nested Access (Elevated Baseline)
    if "." in context.path:
        score += 20
        
    # Rule 3: Repeated Denied Requests
    if context.user_id:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Check for denied requests in the last 10 minutes
        cursor.execute('''
            SELECT COUNT(*) FROM audit_logs 
            WHERE user_id = ? AND decision = 'DENY'
            AND timestamp >= datetime('now', '-10 minutes')
        ''', (context.user_id,))
        recent_denies = cursor.fetchone()[0]
        conn.close()
        
        if recent_denies > 0:
            score += 10
            
    # Cap score at 100
    score = min(score, 100)
    
    # Map to severity level
    if score < 30:
        risk_level = "LOW"
    elif score < 60:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"
        
    return score, risk_level
