"""
RegentClaw — FastAPI dependencies.

get_current_user:
  In DEBUG mode → returns a synthetic admin user (no token required).
  In production → requires a valid Bearer JWT obtained from POST /api/v1/auth/token.

Usage:
  from app.core.deps import get_current_user

  @router.get("/protected")
  async def protected(user = Depends(get_current_user)):
      return {"user": user}
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError

from app.core.config import settings
from app.core.security import decode_access_token

_bearer = HTTPBearer(auto_error=False)

# Synthetic admin used in dev/debug bypass
_DEV_USER = {
    "sub": "dev-admin",
    "role": "admin",
    "email": "admin@regentclaw.local",
    "debug_bypass": True,
}


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    """
    Resolve the current user from a Bearer JWT.

    In DEBUG mode (settings.DEBUG = True) this always returns a synthetic admin
    so that local development and all existing tests work without credentials.
    """
    if settings.DEBUG:
        return _DEV_USER

    # Production path — require a valid Bearer token
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(credentials.credentials)
        sub: str = payload.get("sub", "")
        if not sub:
            raise ValueError("empty sub")
        return payload
    except (JWTError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    """Dependency that enforces role=admin."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin required")
    return user
