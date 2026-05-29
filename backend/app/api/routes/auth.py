"""
RegentClaw — Auth Routes
POST /api/v1/auth/token  → exchange credentials for a Bearer JWT
GET  /api/v1/auth/me     → return the current user (requires valid token)

Default superadmin credentials (change via env vars):
  username: admin
  password: regentclaw-admin

Set ADMIN_USERNAME / ADMIN_PASSWORD in your .env to override.
In production also set SECRET_KEY and DEBUG=false.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from app.core.config import settings
from app.core.security import create_access_token, hash_password, verify_password
from app.core.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["Auth"])

# ── In-process rate limiter for /auth/token (Finding 12) ─────────────────────
# Uses a sliding-window counter keyed by client IP.
# For multi-replica deployments, replace with Redis-backed slowapi.
_RATE_WINDOW   = 60    # seconds
_RATE_MAX      = 10    # attempts per window per IP
_rate_store: dict[str, list[float]] = defaultdict(list)
_rate_lock  = threading.Lock()


def _auth_rate_limit(request: Request) -> None:
    """Dependency: raises 429 if the caller IP exceeds 10 login attempts / minute."""
    ip  = request.client.host if request.client else "unknown"
    now = time.monotonic()
    cutoff = now - _RATE_WINDOW
    with _rate_lock:
        window = [t for t in _rate_store[ip] if t > cutoff]
        if len(window) >= _RATE_MAX:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts — please wait 60 seconds before retrying.",
                headers={"Retry-After": "60"},
            )
        window.append(now)
        _rate_store[ip] = window


# ── Configurable credentials ──────────────────────────────────────────────────
# In production store these hashed in a DB; for now use env-configured pair.

import os as _os

_ADMIN_USERNAME = _os.getenv("ADMIN_USERNAME", "admin")
_ADMIN_PASSWORD = _os.getenv("ADMIN_PASSWORD", "regentclaw-admin")

# Pre-hash at startup so login doesn't do plaintext comparison
_ADMIN_HASH = hash_password(_ADMIN_PASSWORD)

_USERS: dict[str, dict] = {
    _ADMIN_USERNAME: {
        "sub":      _ADMIN_USERNAME,
        "role":     "admin",
        "email":    _os.getenv("ADMIN_EMAIL", "redacted_user"),
        "hashed_password": _ADMIN_HASH,
    },
}


# ── Schemas ───────────────────────────────────────────────────────────────────

class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    expires_in:   int


class UserResponse(BaseModel):
    sub:   str
    role:  str
    email: str


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/token", response_model=TokenResponse)
async def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    _rl: None = Depends(_auth_rate_limit),
):
    """
    Exchange username + password for a Bearer JWT.
    Rate limited to 10 attempts/minute per IP (Finding 12).
    Use with Authorization: Bearer <token> on protected endpoints.
    In DEBUG mode all endpoints bypass auth automatically.
    """
    user = _USERS.get(form.username)
    if not user or not verify_password(form.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(
        data={"sub": user["sub"], "role": user["role"], "email": user["email"]},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return TokenResponse(
        access_token=token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/me", response_model=UserResponse)
async def me(user: dict = Depends(get_current_user)):
    """Return the currently authenticated user's profile."""
    return UserResponse(
        sub=user.get("sub", "unknown"),
        role=user.get("role", "viewer"),
        email=user.get("email", ""),
    )
