from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from app.api.admin_routes import router as admin_router
from app.api.analyses_routes import router as analyses_router
from app.api.auth_routes import router as auth_router
from app.api.billing_routes import router as billing_router
from app.api.routes import router
from app.core.config import get_settings
from app.db.seed import seed
from app.db.session import init_db

limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    try:
        seed()
    except Exception as e:
        print(f"[startup] seed skipped/failed: {e}")
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "SecureCode Copilot — Detect, explain, and auto-fix security "
            "vulnerabilities in multi-language source code. SaaS MVP with auth, quota, billing mock."
        ),
        lifespan=lifespan,
    )
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list + ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(router, prefix=settings.api_prefix)
    app.include_router(auth_router, prefix=settings.api_prefix)
    app.include_router(analyses_router, prefix=settings.api_prefix)
    app.include_router(billing_router, prefix=settings.api_prefix)
    app.include_router(admin_router, prefix=settings.api_prefix)
    return app


app = create_app()
