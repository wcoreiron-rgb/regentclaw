"""
RegentClaw — Security utilities: password hashing + JWT creation/verification.

In DEBUG mode (settings.DEBUG = True, the default) auth is a no-op so that
local dev still works without credentials.  Set DEBUG=False (and a real
SECRET_KEY) when deploying to staging/production.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import jwt as pyjwt
from jwt.exceptions import InvalidTokenError as JWTError  # noqa: F401 — re-exported for deps.py
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__truncate_error=True)


# ── Password helpers ──────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ── JWT helpers ───────────────────────────────────────────────────────────────

def create_access_token(
    data: dict[str, Any],
    expires_delta: timedelta | None = None,
) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode["exp"] = expire
    # PyJWT — explicit algorithm, no alg:none confusion possible
    return pyjwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """Raises jwt.InvalidTokenError on invalid/expired tokens."""
    return pyjwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM],
        options={"require": ["exp", "sub"]},  # enforce mandatory claims
    )
