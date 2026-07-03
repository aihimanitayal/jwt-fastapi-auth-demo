"""JWT creation, verification, and refresh-token storage utilities."""

import os
import uuid
from datetime import datetime, timedelta, timezone

import jwt

SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dev-only-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = 15
REFRESH_TOKEN_DAYS = 7

# In-memory store for demo purposes only.
# In production: use Redis or a DB table, keyed by user_id, storing the
# current valid refresh token (enables rotation + revocation).
active_refresh_tokens: dict[str, str] = {}


def create_access_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "type": "access",
        "jti": str(uuid.uuid4()),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "type": "refresh",
        "jti": str(uuid.uuid4()),
        "exp": datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_DAYS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str, expected_type: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")

    if payload.get("type") != expected_type:
        raise ValueError(f"Expected {expected_type} token, got {payload.get('type')}")

    return payload


def issue_tokens(user_id: str) -> dict:
    """Issue a new access + refresh token pair, storing the refresh token for rotation."""
    access = create_access_token(user_id)
    refresh = create_refresh_token(user_id)
    active_refresh_tokens[user_id] = refresh
    return {"access_token": access, "refresh_token": refresh}


def rotate_refresh_token(refresh_token: str) -> dict:
    """Validate a refresh token, reject if it's not the current one on file (rotation
    check), then issue and store a brand-new pair."""
    payload = verify_token(refresh_token, expected_type="refresh")
    user_id = payload["sub"]

    if active_refresh_tokens.get(user_id) != refresh_token:
        raise ValueError("Refresh token has been revoked or already used")

    return issue_tokens(user_id)


def revoke_refresh_token(user_id: str) -> None:
    active_refresh_tokens.pop(user_id, None)
