"""Seed database with plans and demo users."""

from __future__ import annotations

from datetime import datetime, timezone

from app.billing.plans import PLAN_CATALOG, features_json
from app.core.security import hash_password
from app.db.models import Plan, User, UserRole, SubscriptionStatus
from app.db.session import SessionLocal, init_db


def upsert_plans(db) -> dict[str, Plan]:
    by_code = {}
    for raw in PLAN_CATALOG:
        plan = db.query(Plan).filter(Plan.code == raw["code"]).one_or_none()
        if not plan:
            plan = Plan(code=raw["code"])
            db.add(plan)
        plan.name = raw["name"]
        plan.description = raw["description"]
        plan.price_monthly_vnd = raw["price_monthly_vnd"]
        plan.price_yearly_vnd = raw["price_yearly_vnd"]
        plan.monthly_limit = raw["monthly_limit"]
        plan.max_lines = raw["max_lines"]
        plan.max_members = raw["max_members"]
        plan.history_days = raw["history_days"]
        plan.features_json = features_json(raw)
        plan.sort_order = raw.get("sort_order", 0)
        plan.is_public = True
        by_code[raw["code"]] = plan
    db.commit()
    for p in by_code.values():
        db.refresh(p)
    return by_code


def upsert_user(
    db,
    *,
    email: str,
    full_name: str,
    password: str,
    role: UserRole,
    plan: Plan,
) -> User:
    user = db.query(User).filter(User.email == email).one_or_none()
    if not user:
        user = User(email=email)
        db.add(user)
    user.full_name = full_name
    user.hashed_password = hash_password(password)
    user.role = role
    user.is_active = True
    user.is_locked = False
    user.email_verified = True
    user.plan_id = plan.id
    user.monthly_limit = plan.monthly_limit
    user.used_this_month = 0
    user.quota_reset_at = datetime(datetime.now(timezone.utc).year, datetime.now(timezone.utc).month % 12 + 1 or 12, 1, tzinfo=timezone.utc)
    # fix quota reset: next month 1st
    now = datetime.now(timezone.utc)
    month = 1 if now.month == 12 else now.month + 1
    year = now.year + (1 if now.month == 12 else 0)
    user.quota_reset_at = datetime(year, month, 1, tzinfo=timezone.utc)
    user.subscription_status = SubscriptionStatus.ACTIVE
    user.subscription_start_at = now
    db.commit()
    db.refresh(user)
    return user


def seed() -> None:
    init_db()
    db = SessionLocal()
    try:
        plans = upsert_plans(db)
        # Remove obsolete .local demo accounts (email-validator rejects .local)
        for old in (
            "admin@securecode.local",
            "free@securecode.local",
            "pro@securecode.local",
            "team@securecode.local",
        ):
            row = db.query(User).filter(User.email == old).one_or_none()
            if row:
                db.delete(row)
        db.commit()

        upsert_user(
            db,
            email="admin@securecode.dev",
            full_name="SecureCode Admin",
            password="Admin123!",
            role=UserRole.SUPER_ADMIN,
            plan=plans["pro"],
        )
        upsert_user(
            db,
            email="free@securecode.dev",
            full_name="Demo Free",
            password="Free1234!",
            role=UserRole.USER,
            plan=plans["free"],
        )
        upsert_user(
            db,
            email="pro@securecode.dev",
            full_name="Demo Pro",
            password="Pro12345!",
            role=UserRole.USER,
            plan=plans["pro"],
        )
        upsert_user(
            db,
            email="team@securecode.dev",
            full_name="Demo Team",
            password="Team1234!",
            role=UserRole.USER,
            plan=plans["team"],
        )
        print("[seed] plans + demo users ready")
        print("  admin@securecode.dev / Admin123!")
        print("  free@securecode.dev / Free1234!")
        print("  pro@securecode.dev / Pro12345!")
        print("  team@securecode.dev / Team1234!")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
