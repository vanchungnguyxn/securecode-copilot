"""Auth routes."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, remaining_usage
from app.billing.plans import PLAN_CATALOG
from app.core.config import get_settings
from app.core.security import create_access_token, hash_password, verify_password
from app.db.models import PasswordResetToken, Plan, SubscriptionStatus, User, UserRole
from app.db.session import get_db
from app.schemas.saas import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    MessageOut,
    RegisterRequest,
    ResetPasswordRequest,
    TokenResponse,
    UpdateProfileRequest,
    UserOut,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def to_user_out(user: User) -> UserOut:
    plan = user.plan
    return UserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role.value if hasattr(user.role, "value") else str(user.role),
        locale=user.locale,
        theme=user.theme,
        plan_code=plan.code if plan else None,
        plan_name=plan.name if plan else None,
        monthly_limit=user.monthly_limit,
        used_this_month=user.used_this_month,
        remaining_usage=remaining_usage(user),
        quota_reset_at=user.quota_reset_at,
        subscription_status=user.subscription_status.value
        if hasattr(user.subscription_status, "value")
        else str(user.subscription_status),
        email_verified=user.email_verified,
        is_active=user.is_active,
    )


@router.post("/register", response_model=TokenResponse)
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    if body.password != body.confirm_password:
        raise HTTPException(status_code=400, detail="Xác nhận mật khẩu không khớp")
    existing = db.query(User).filter(User.email == body.email.lower()).one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Email đã được sử dụng")

    free = db.query(Plan).filter(Plan.code == "free").one_or_none()
    if not free:
        raise HTTPException(status_code=500, detail="Chưa seed gói Free — chạy: python -m app.db.seed")

    now = datetime.now(timezone.utc)
    month = 1 if now.month == 12 else now.month + 1
    year = now.year + (1 if now.month == 12 else 0)
    user = User(
        email=body.email.lower().strip(),
        full_name=body.full_name.strip(),
        hashed_password=hash_password(body.password),
        role=UserRole.USER,
        plan_id=free.id,
        monthly_limit=free.monthly_limit,
        used_this_month=0,
        quota_reset_at=datetime(year, month, 1, tzinfo=timezone.utc),
        subscription_status=SubscriptionStatus.ACTIVE,
        subscription_start_at=now,
        email_verified=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    settings = get_settings()
    if settings.email_enabled:
        # real email later
        pass
    else:
        print(f"[email-mock] verify account for {user.email} (dev — auto noted as pending)")

    token = create_access_token(str(user.id), {"role": user.role.value})
    return TokenResponse(access_token=token, user=to_user_out(user))


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    # Rate-limit: basic per-IP via SlowAPI if app.state.limiter exists
    limiter = getattr(request.app.state, "limiter", None)
    if limiter is not None:
        # Declared limit enforced when decorator used; here we keep soft guard note
        pass
    user = db.query(User).filter(User.email == body.email.lower()).one_or_none()
    # Generic error — don't leak which field is wrong
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Email hoặc mật khẩu không đúng")
    if user.is_locked or not user.is_active:
        raise HTTPException(status_code=403, detail="Tài khoản bị khóa hoặc vô hiệu")

    token = create_access_token(str(user.id), {"role": user.role.value})
    return TokenResponse(access_token=token, user=to_user_out(user))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return to_user_out(user)


@router.patch("/me", response_model=UserOut)
def update_me(body: UpdateProfileRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if body.full_name is not None:
        user.full_name = body.full_name
    if body.locale is not None:
        user.locale = body.locale
    if body.theme is not None:
        user.theme = body.theme
    if body.timezone is not None:
        user.timezone = body.timezone
    db.add(user)
    db.commit()
    db.refresh(user)
    return to_user_out(user)


@router.post("/change-password", response_model=MessageOut)
def change_password(
    body: ChangePasswordRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    if not verify_password(body.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Mật khẩu hiện tại không đúng")
    user.hashed_password = hash_password(body.new_password)
    db.add(user)
    db.commit()
    return MessageOut(message="Đã đổi mật khẩu")


@router.post("/forgot-password", response_model=MessageOut)
def forgot_password(body: ForgotPasswordRequest, db: Session = Depends(get_db)):
    # Always same message
    msg = "Nếu email tồn tại, hướng dẫn đặt lại mật khẩu đã được gửi."
    user = db.query(User).filter(User.email == body.email.lower()).one_or_none()
    if user:
        token = secrets.token_urlsafe(32)
        row = PasswordResetToken(
            user_id=user.id,
            token=token,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
        )
        db.add(row)
        db.commit()
        settings = get_settings()
        print(f"[email-mock] reset link: {settings.app_url}/reset-password?token={token}")
    return MessageOut(message=msg)


@router.post("/reset-password", response_model=MessageOut)
def reset_password(body: ResetPasswordRequest, db: Session = Depends(get_db)):
    row = db.query(PasswordResetToken).filter(PasswordResetToken.token == body.token).one_or_none()
    if not row or row.used or row.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Token không hợp lệ hoặc đã hết hạn")
    user = db.get(User, row.user_id)
    if not user:
        raise HTTPException(status_code=400, detail="Token không hợp lệ")
    user.hashed_password = hash_password(body.new_password)
    row.used = True
    db.add(user)
    db.add(row)
    db.commit()
    return MessageOut(message="Đã đặt lại mật khẩu")


@router.post("/logout", response_model=MessageOut)
def logout(user: User = Depends(get_current_user)):
    # JWT is stateless; client discards token
    return MessageOut(message="Đã đăng xuất")
