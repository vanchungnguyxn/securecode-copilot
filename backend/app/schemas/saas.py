"""Auth request/response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


class RegisterRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    confirm_password: str
    accept_terms: bool

    @field_validator("accept_terms")
    @classmethod
    def must_accept(cls, v: bool) -> bool:
        if not v:
            raise ValueError("Bạn cần đồng ý điều khoản")
        return v

    @field_validator("password")
    @classmethod
    def strong_password(cls, v: str) -> str:
        if not any(c.isupper() for c in v) or not any(c.islower() for c in v) or not any(c.isdigit() for c in v):
            raise ValueError("Mật khẩu cần chữ hoa, chữ thường và số")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    remember: bool = False


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: "UserOut"


class UserOut(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    locale: str
    theme: str
    plan_code: Optional[str] = None
    plan_name: Optional[str] = None
    monthly_limit: int
    used_this_month: int
    remaining_usage: int
    quota_reset_at: Optional[datetime] = None
    subscription_status: str
    email_verified: bool
    is_active: bool

    model_config = {"from_attributes": True}


class UpdateProfileRequest(BaseModel):
    full_name: Optional[str] = Field(default=None, min_length=2, max_length=120)
    locale: Optional[str] = None
    theme: Optional[str] = None
    timezone: Optional[str] = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=128)


class PlanOut(BaseModel):
    code: str
    name: str
    description: str
    price_monthly_vnd: int
    price_yearly_vnd: int
    monthly_limit: int
    max_lines: int
    max_members: int
    history_days: int
    features: List[str]
    popular: bool = False
    contact_only: bool = False


class MessageOut(BaseModel):
    message: str
    detail: Optional[str] = None
