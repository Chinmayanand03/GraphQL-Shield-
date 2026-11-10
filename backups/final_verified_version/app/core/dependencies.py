import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.core.security import verify_token

security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    """
    Dependency that extracts and validates the JWT token from the Authorization header.
    Returns the decoded token payload (the user context).
    """
    token = credentials.credentials
    try:
        payload = verify_token(token)
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
