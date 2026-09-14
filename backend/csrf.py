"""CSRF protection middleware and utilities.

Uses the double-submit cookie pattern backed by itsdangerous.
- A CSRF token is generated per-session and stored in the signed session.
- Browser-originated state-changing requests (POST /api/threats/*/override)
  must include it as X-CSRF-Token header.
- The Pub/Sub push endpoint is exempt (uses Google JWT auth instead).
- GET requests are always exempt.
"""
from __future__ import annotations

import logging
import secrets
from typing import Set

from fastapi import HTTPException, Request
from itsdangerous import BadSignature, URLSafeTimedSerializer

from .config import get_settings

logger = logging.getLogger(__name__)

# Endpoints that are excluded from CSRF checks even if POST
# (they use their own authentication: Google JWT, API key, etc.)
CSRF_EXEMPT_PREFIXES: Set[str] = {
    "/auth/",       # OAuth callback is GET; login POST is server-initiated
    "/api/pubsub/", # Authenticated by Google OIDC JWT
    "/api/geo/",    # Geolocation / IP query utility endpoints
}

CSRF_HEADER = "X-CSRF-Token"
CSRF_SESSION_KEY = "csrf_token"


def _get_signer() -> URLSafeTimedSerializer:
    settings = get_settings()
    return URLSafeTimedSerializer(settings.SESSION_SECRET, salt="csrf")


def get_or_create_csrf_token(request: Request) -> str:
    """Get the CSRF token from the session, creating one if absent."""
    token = request.session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        request.session[CSRF_SESSION_KEY] = token
    return token


def validate_csrf_token(request: Request) -> None:
    """Validate the CSRF token from the X-CSRF-Token header.

    Raises:
        HTTPException 403 if token is missing or invalid.
    """
    path = request.url.path

    # Skip non-state-changing methods
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return

    # Skip exempt prefixes (Pub/Sub uses Google JWT; OAuth is GET)
    for prefix in CSRF_EXEMPT_PREFIXES:
        if path.startswith(prefix):
            return

    session_token = request.session.get(CSRF_SESSION_KEY)
    header_token = request.headers.get(CSRF_HEADER)

    if not session_token or not header_token:
        logger.warning("CSRF token missing: path=%s method=%s", path, request.method)
        raise HTTPException(status_code=403, detail="CSRF token missing")

    if not secrets.compare_digest(session_token, header_token):
        logger.warning("CSRF token mismatch: path=%s", path)
        raise HTTPException(status_code=403, detail="CSRF token invalid")
