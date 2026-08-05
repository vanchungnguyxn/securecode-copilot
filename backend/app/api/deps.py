"""FastAPI dependencies: DB session, current user, roles."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.security import try_decode_token
from app.db.models import User, UserRole
from app.db.session import get_db

bearer = HTTPBearer(auto_error=False)


def get_current_user_optional(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    db: Session = Depends(get_db),
) -> Optional[User]:
    if not creds or not creds.credentials:
        return None
    payload = try_decode_token(creds.credentials)
    if not payload or payload.get("type") != "access":
        return None
    sub = payload.get("sub")
    if not sub:
        return None
    user = db.get(User, int(sub))
    if not user or not user.is_active or user.is_locked:
        return None
    _maybe_reset_quota(user, db)
    return user


def get_current_user(user: Optional[User] = Depends(get_current_user_optional)) -> User:
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Chưa đăng nhập")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Không có quyền quản trị")
    return user


def _maybe_reset_quota(user: User, db: Session) -> None:
    now = datetime.now(timezone.utc)
    reset_at = user.quota_reset_at
    if reset_at is None:
        user.quota_reset_at = _next_month(now)
        db.add(user)
        db.commit()
        return
    if reset_at.tzinfo is None:
        reset_at = reset_at.replace(tzinfo=timezone.utc)
    if now >= reset_at:
        user.used_this_month = 0
        user.quota_reset_at = _next_month(now)
        db.add(user)
        db.commit()


def _next_month(now: datetime) -> datetime:
    year = now.year + (1 if now.month == 12 else 0)
    month = 1 if now.month == 12 else now.month + 1
    return datetime(year, month, 1, tzinfo=timezone.utc)


def remaining_usage(user: User) -> int:
    return max(0, int(user.monthly_limit) - int(user.used_this_month))
