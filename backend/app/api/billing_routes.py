"""Plans + mock billing."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.auth_routes import to_user_out
from app.api.deps import get_current_user
from app.billing.plans import PLAN_CATALOG
from app.core.config import get_settings
from app.db.models import (
    AuditLog,
    Payment,
    PaymentStatus,
    Plan,
    Subscription,
    SubscriptionStatus,
    User,
)
from app.db.session import get_db
from app.schemas.saas import MessageOut, PlanOut, UserOut

router = APIRouter(tags=["billing"])


def plan_to_out(p: Plan) -> PlanOut:
    raw = next((x for x in PLAN_CATALOG if x["code"] == p.code), {})
    try:
        features = json.loads(p.features_json or "[]")
    except json.JSONDecodeError:
        features = []
    return PlanOut(
        code=p.code,
        name=p.name,
        description=p.description,
        price_monthly_vnd=p.price_monthly_vnd,
        price_yearly_vnd=p.price_yearly_vnd,
        monthly_limit=p.monthly_limit,
        max_lines=p.max_lines,
        max_members=p.max_members,
        history_days=p.history_days,
        features=features,
        popular=bool(raw.get("popular")),
        contact_only=bool(raw.get("contact_only")),
    )


@router.get("/plans", response_model=List[PlanOut])
def list_plans(db: Session = Depends(get_db)):
    rows = db.query(Plan).filter(Plan.is_public.is_(True)).order_by(Plan.sort_order).all()
    if not rows:
        # fallback catalog without DB
        return [
            PlanOut(
                code=p["code"],
                name=p["name"],
                description=p["description"],
                price_monthly_vnd=p["price_monthly_vnd"],
                price_yearly_vnd=p["price_yearly_vnd"],
                monthly_limit=p["monthly_limit"],
                max_lines=p["max_lines"],
                max_members=p["max_members"],
                history_days=p["history_days"],
                features=p.get("features") or [],
                popular=bool(p.get("popular")),
                contact_only=bool(p.get("contact_only")),
            )
            for p in PLAN_CATALOG
        ]
    return [plan_to_out(p) for p in rows]


class CheckoutRequest(BaseModel):
    plan_code: str
    billing_cycle: str = Field(default="monthly", pattern="^(monthly|yearly)$")


class CheckoutOut(BaseModel):
    payment_id: int
    transaction_id: str
    amount: int
    currency: str
    status: str
    checkout_url: str
    mock: bool = True


@router.post("/billing/checkout", response_model=CheckoutOut)
def checkout(body: CheckoutRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    plan = db.query(Plan).filter(Plan.code == body.plan_code).one_or_none()
    if not plan:
        raise HTTPException(status_code=404, detail="Không tìm thấy gói")
    raw = next((x for x in PLAN_CATALOG if x["code"] == plan.code), {})
    if raw.get("contact_only"):
        raise HTTPException(status_code=400, detail="Gói Enterprise — vui lòng liên hệ tư vấn")

    amount = plan.price_yearly_vnd if body.billing_cycle == "yearly" else plan.price_monthly_vnd
    txn = f"mock_{uuid.uuid4().hex[:16]}"
    payment = Payment(
        user_id=user.id,
        plan_id=plan.id,
        amount=amount,
        currency="VND",
        status=PaymentStatus.PENDING,
        provider="mock",
        transaction_id=txn,
        billing_cycle=body.billing_cycle,
    )
    db.add(payment)
    db.commit()
    db.refresh(payment)

    settings = get_settings()
    return CheckoutOut(
        payment_id=payment.id,
        transaction_id=txn,
        amount=amount,
        currency="VND",
        status=payment.status.value,
        checkout_url=f"{settings.app_url}/dashboard/billing?pay={txn}",
        mock=True,
    )


class MockPayRequest(BaseModel):
    transaction_id: str


@router.post("/billing/mock-pay", response_model=UserOut)
def mock_pay(body: MockPayRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    settings = get_settings()
    if not settings.billing_mock:
        raise HTTPException(status_code=400, detail="Mock billing đang tắt")

    payment = db.query(Payment).filter(Payment.transaction_id == body.transaction_id).one_or_none()
    if not payment or payment.user_id != user.id:
        raise HTTPException(status_code=404, detail="Giao dịch không tồn tại")
    if payment.status == PaymentStatus.PAID:
        return to_user_out(user)

    plan = db.get(Plan, payment.plan_id)
    if not plan:
        raise HTTPException(status_code=400, detail="Gói không hợp lệ")

    payment.status = PaymentStatus.PAID
    payment.paid_at = datetime.now(timezone.utc)
    db.add(payment)

    user.plan_id = plan.id
    user.monthly_limit = plan.monthly_limit
    user.subscription_status = SubscriptionStatus.ACTIVE
    user.subscription_start_at = datetime.now(timezone.utc)
    db.add(user)

    db.add(
        Subscription(
            user_id=user.id,
            plan_id=plan.id,
            status=SubscriptionStatus.ACTIVE,
            billing_cycle=payment.billing_cycle,
            provider="mock",
            provider_ref=payment.transaction_id,
        )
    )
    db.add(
        AuditLog(
            actor_id=user.id,
            action="billing.mock_pay",
            target_type="payment",
            target_id=str(payment.id),
            detail=f"Upgraded to {plan.code}",
        )
    )
    db.commit()
    db.refresh(user)
    return to_user_out(user)


@router.get("/billing/payments")
def my_payments(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(Payment).filter(Payment.user_id == user.id).order_by(Payment.created_at.desc()).limit(50).all()
    return [
        {
            "id": p.id,
            "transaction_id": p.transaction_id,
            "amount": p.amount,
            "currency": p.currency,
            "status": p.status.value,
            "billing_cycle": p.billing_cycle,
            "created_at": p.created_at,
            "paid_at": p.paid_at,
            "plan_id": p.plan_id,
        }
        for p in rows
    ]


@router.post("/billing/cancel", response_model=MessageOut)
def cancel_renewal(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user.subscription_status = SubscriptionStatus.CANCELLED
    db.add(user)
    db.add(
        AuditLog(
            actor_id=user.id,
            action="billing.cancel",
            target_type="user",
            target_id=str(user.id),
            detail="User cancelled auto-renew (mock)",
        )
    )
    db.commit()
    return MessageOut(message="Đã ghi nhận huỷ gia hạn tự động (có hiệu lực cuối chu kỳ hiện tại).")
