import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt

from app.config import settings


def create_access_token(
    user_id: int,
    role: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a signed JWT access token with a timezone-aware expiry.

    The token carries an ID (so it can be revoked on logout) and the account's
    session version (so logging out everywhere or changing the password ends it).
    The role is informational: requests use the role stored in the database.
    """
    from app.core.accounts import token_version

    now = datetime.now(timezone.utc)
    duration = (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.ACCESS_TOKEN_MINUTES)
    )
    expire = now + duration

    payload = {
        "user_id": user_id,
        "role": role,
        "iat": now,
        "exp": expire,
        "jti": secrets.token_hex(16),
        "ver": token_version(user_id),
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

