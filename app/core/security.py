from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt

from app.config import settings


def create_access_token(
    user_id: int,
    role: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a signed JWT access token with a timezone-aware expiry."""
    now = datetime.now(timezone.utc)
    duration = (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=60)
    )
    expire = now + duration

    payload = {
        "user_id": user_id,
        "role": role,
        "exp": expire,
    }

    return jwt.encode(
        payload,
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )


def verify_token(token: str) -> dict:
    """Verify a JWT and return its decoded claims."""
    return jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
    )

