from dataclasses import dataclass
from typing import Optional, Dict, Any

@dataclass
class AuthorizationContext:
    """
    Structured context containing all information necessary for the 
    Policy Engine to make a zero-trust authorization decision.
    """
    user_id: int
    role: str
    operation: str
    object_type: str
    object_id: int
    path: str
    owner_id: Optional[int]
    metadata: Dict[str, Any]

from .risk_engine import calculate_risk

class PolicyEngine:
    """
    Rule-based Policy Engine.
    Evaluates the authorization context against predefined security policies.
    """
    def __init__(self):
        pass
        
    def evaluate(self, context: AuthorizationContext) -> dict:
        """
        Returns a decision dictionary including risk scoring.
        """
        # Validate Context
        if not context.user_id or not context.object_type or context.object_id is None:
            base_decision, reason = "DENY", "INVALID_CONTEXT"
            
        # Policy 1: Object must exist to be accessed
        elif context.owner_id is None:
            base_decision, reason = "DENY", "OBJECT_NOT_FOUND"
            
        # Policy 2: Admins have unrestricted access to all resources
        elif context.role.upper() == "ADMIN":
            base_decision, reason = "ALLOW", "ADMIN_OVERRIDE"
            
        # Policy 3: Owner can access their own object
        elif str(context.user_id) == str(context.owner_id):
            base_decision, reason = "ALLOW", "OWNER_MATCH"
            
        # Policy 4: Unauthorized nested resource access is explicitly denied
        elif "." in context.path:
            base_decision, reason = "DENY", "NESTED_AUTHORIZATION_VIOLATION"
            
        # Default Deny (Zero Trust: BOLA protection fallback)
        else:
            base_decision, reason = "DENY", "OWNERSHIP_MISMATCH"
            
        # Phase 8: Deterministic Risk Scoring
        score, risk_level = calculate_risk(context, reason)
        
        return {
            "decision": base_decision,
            "reason": reason,
            "risk_score": score,
            "risk_level": risk_level
        }
