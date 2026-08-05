"""Admin APIs."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.db.models import Analysis, AuditLog, Payment, PaymentStatus, Plan, User, UserRole
from app.db.session import get_db

router = APIRouter(prefix="/admin", tags=["admin"])


class AdjustQuotaRequest(BaseModel):
    delta: int = Field(..., description="Positive to add, negative to subtract used or change limit")
    set_limit: Optional[int] = None


class LockRequest(BaseModel):
    locked: bool


@router.get("/stats")
def stats(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    total_users = db.query(func.count(User.id)).scalar() or 0
    paid = (
        db.query(func.count(User.id))
        .join(Plan, User.plan_id == Plan.id)
        .filter(Plan.code.in_(["pro", "team", "enterprise"]))
        .scalar()
        or 0
    )
    analyses = db.query(func.count(Analysis.id)).scalar() or 0
    revenue = (
        db.query(func.coalesce(func.sum(Payment.amount), 0))
        .filter(Payment.status == PaymentStatus.PAID)
        .scalar()
        or 0
    )
    failed_pay = (
        db.query(func.count(Payment.id)).filter(Payment.status == PaymentStatus.FAILED).scalar() or 0
    )
    return {
        "total_users": total_users,
        "paying_users": paid,
        "total_analyses": analyses,
        "mrr_estimate_vnd": revenue,
        "failed_payments": failed_pay,
        "ai_cost_estimate_vnd": analyses * 150,
    }


@router.get("/users")
def list_users(
    q: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    query = db.query(User)
    if q:
        like = f"%{q}%"
        query = query.filter((User.email.ilike(like)) | (User.full_name.ilike(like)))
    rows = query.order_by(User.created_at.desc()).offset(offset).limit(min(limit, 100)).all()
    return [
        {
            "id": u.id,
            "email": u.email,
            "full_name": u.full_name,
            "role": u.role.value,
            "plan": u.plan.code if u.plan else None,
            "used_this_month": u.used_this_month,
            "monthly_limit": u.monthly_limit,
            "is_locked": u.is_locked,
            "is_active": u.is_active,
            "created_at": u.created_at,
        }
        for u in rows
    ]


@router.post("/users/{user_id}/lock")
def lock_user(
    user_id: int,
    body: LockRequest,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    if u.role == UserRole.SUPER_ADMIN and admin.role != UserRole.SUPER_ADMIN:
        raise HTTPException(status_code=403, detail="Không thể khóa SUPER_ADMIN")
    u.is_locked = body.locked
    db.add(u)
    db.add(
        AuditLog(
            actor_id=admin.id,
            action="admin.lock_user" if body.locked else "admin.unlock_user",
            target_type="user",
            target_id=str(u.id),
            detail=u.email,
        )
    )
    db.commit()
    return {"ok": True}


@router.post("/users/{user_id}/quota")
def adjust_quota(
    user_id: int,
    body: AdjustQuotaRequest,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    if body.set_limit is not None:
        u.monthly_limit = max(0, body.set_limit)
    else:
        u.used_this_month = max(0, int(u.used_this_month) - int(body.delta))
    db.add(u)
    db.add(
        AuditLog(
            actor_id=admin.id,
            action="admin.adjust_quota",
            target_type="user",
            target_id=str(u.id),
            detail=str(body.model_dump()),
        )
    )
    db.commit()
    return {
        "ok": True,
        "monthly_limit": u.monthly_limit,
        "used_this_month": u.used_this_month,
    }


@router.get("/payments")
def admin_payments(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(Payment).order_by(Payment.created_at.desc()).limit(100).all()
    return [
        {
            "id": p.id,
            "user_id": p.user_id,
            "amount": p.amount,
            "status": p.status.value,
            "transaction_id": p.transaction_id,
            "created_at": p.created_at,
            "paid_at": p.paid_at,
        }
        for p in rows
    ]


@router.get("/analyses")
def admin_analyses(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(Analysis).order_by(Analysis.created_at.desc()).limit(100).all()
    return [
        {
            "id": a.id,
            "user_id": a.user_id,
            "filename": a.filename,
            "language": a.language,
            "vulnerability_count": a.vulnerability_count,
            "status": a.status.value,
            "created_at": a.created_at,
        }
        for a in rows
    ]


@router.get("/audit-logs")
def audit_logs(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(200).all()
    return [
        {
            "id": r.id,
            "actor_id": r.actor_id,
            "action": r.action,
            "target_type": r.target_type,
            "target_id": r.target_id,
            "detail": r.detail,
            "created_at": r.created_at,
        }
        for r in rows
    ]


@router.get("/plans")
def admin_plans(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    return [
        {
            "id": p.id,
            "code": p.code,
            "name": p.name,
            "price_monthly_vnd": p.price_monthly_vnd,
            "monthly_limit": p.monthly_limit,
            "max_lines": p.max_lines,
        }
        for p in db.query(Plan).order_by(Plan.sort_order).all()
    ]
