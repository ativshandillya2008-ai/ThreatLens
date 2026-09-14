"""ThreatLens Email Threat Detection — FastAPI application entry point."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .auth.router import router as auth_router
from .config import get_settings
from .csrf import get_or_create_csrf_token, validate_csrf_token
from .database import close_db, create_tables
from .gmail.pubsub import schedule_watch_renewal
from .gmail.router import router as gmail_router
from .threats.retention import schedule_retention_purge
from .threats.router import router as threats_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup / shutdown lifecycle."""
    settings = get_settings()
    logger.info("Starting ThreatLens Email Threat Detection (port %s)", settings.PORT)

    await create_tables()
    # Schedule Gmail watch renewal (runs every 6 days)
    renewal_task = asyncio.create_task(schedule_watch_renewal())
    # Schedule audit log retention purge (runs every 24 hours)
    retention_task = asyncio.create_task(schedule_retention_purge())

    yield

    renewal_task.cancel()
    retention_task.cancel()
    try:
        await asyncio.gather(renewal_task, retention_task, return_exceptions=True)
    except asyncio.CancelledError:
        pass
    await close_db()
    logger.info("Shutdown complete")


app = FastAPI(
    title="ThreatLens Email Threat Detection",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

settings = get_settings()

# ── Session middleware ──────────────────────────────────────────────────────
# Flags are set explicitly:
#   https_only=True  → Secure flag (cookie only sent over HTTPS)
#   same_site="lax"  → SameSite=Lax (blocks cross-site POST, allows top-level nav)
# In local dev set SECURE_COOKIES=false via env to allow http://127.0.0.1
_secure_cookies = not settings.DEBUG  # False in DEBUG mode only

# ── CSRF enforcement middleware (innermost of the stack) ────────────────────
from starlette.middleware.base import BaseHTTPMiddleware  # noqa: E402

class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        """Enforce CSRF token on all state-changing browser-originated requests."""
        try:
            validate_csrf_token(request)
        except Exception as exc:
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": str(exc)}, status_code=403)
        return await call_next(request)

app.add_middleware(CSRFMiddleware)

# ── Session Middleware (must wrap CSRFMiddleware so request.session is available)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SESSION_SECRET,
    session_cookie=settings.SESSION_COOKIE_NAME,
    max_age=settings.SESSION_MAX_AGE,
    https_only=_secure_cookies,   # Secure flag: False in dev, True in prod
    same_site="lax",              # SameSite=Lax — blocks CSRF from cross-site POSTs
)

# ── CORS Middleware (outermost) ─────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[f"http://{settings.HOST}:{settings.PORT}"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "X-CSRF-Token"],
)


# ── API Routers ──────────────────────────────────────────────────────────────
app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(gmail_router, prefix="/api/gmail", tags=["gmail"])
app.include_router(threats_router, prefix="/api/threats", tags=["threats"])

from .gmail.pubsub import router as pubsub_router  # noqa: E402
app.include_router(pubsub_router, prefix="/api/pubsub", tags=["pubsub"])

from .agent.router import router as agent_router  # noqa: E402
app.include_router(agent_router, prefix="/api/agent", tags=["agent"])

from .geo.router import router as geo_router  # noqa: E402
app.include_router(geo_router, prefix="/api/geo", tags=["geo"])


# ── CSRF token endpoint ─────────────────────────────────────────────────────
from fastapi.responses import JSONResponse  # noqa: E402

@app.get("/api/csrf-token", include_in_schema=False)
async def csrf_token_endpoint(request: Request):
    """Return a CSRF token for the current session.
    The frontend fetches this once on load and includes it in all mutating requests.
    """
    token = get_or_create_csrf_token(request)
    return JSONResponse({"csrf_token": token})


# ── Static Frontend ──────────────────────────────────────────────────────────
FRONTEND_DIST = Path(__file__).parent.parent / "frontend" / "dist"

if (FRONTEND_DIST / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="assets")


@app.get("/", include_in_schema=False)
async def serve_root():
    """Serve the React SPA for the root route."""
    index = FRONTEND_DIST / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return {"message": "ThreatLens Email Threat Detection API", "docs": "/api/docs"}


@app.get("/{full_path:path}", include_in_schema=False)
async def serve_spa(full_path: str):
    """Serve the React SPA for all non-API routes."""
    index = FRONTEND_DIST / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return {"message": "ThreatLens Email Threat Detection API", "docs": "/api/docs"}

