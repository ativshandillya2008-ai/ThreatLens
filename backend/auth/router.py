"""OAuth2 authentication routes.

GET  /auth/login       — initiates PKCE OAuth flow
GET  /auth/callback    — handles Google callback, stores tokens
POST /auth/logout      — revokes tokens, clears session
GET  /auth/me          — returns current user info from session
"""
from __future__ import annotations

import logging
import secrets

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from ..config import get_settings
from .oauth import (
    build_authorization_url,
    exchange_code_for_tokens,
    generate_pkce_pair,
    get_userinfo,
    revoke_token,
)
from .token_store import delete_tokens, store_tokens

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/login")
async def login(request: Request) -> RedirectResponse:
    """Initiate the Google OAuth2 PKCE flow.

    Stores the code_verifier and state in the server-side session.
    Redirects the browser to Google's consent screen.
    """
    settings = get_settings()
    code_verifier, code_challenge = generate_pkce_pair()
    state = secrets.token_urlsafe(32)

    # Automatically detect redirect_uri based on current request host & scheme
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
    if host and ("trycloudflare.com" in host or "127.0.0.1" in host or "localhost" in host):
        redirect_uri = f"{scheme}://{host}/auth/callback"
    else:
        redirect_uri = settings.OAUTH_REDIRECT_URI

    # Store in server-side session (signed cookie)
    request.session["oauth_state"] = state
    request.session["oauth_code_verifier"] = code_verifier
    request.session["oauth_redirect_uri"] = redirect_uri

    auth_url = build_authorization_url(state=state, code_challenge=code_challenge, redirect_uri=redirect_uri)
    logger.info("Initiating OAuth flow, state=%s, redirect_uri=%s", state[:8] + "...", redirect_uri)
    return RedirectResponse(url=auth_url)


def _frontend_redirect(path: str) -> RedirectResponse:
    settings = get_settings()
    base = settings.FRONTEND_URL.rstrip("/") if settings.FRONTEND_URL else ""
    return RedirectResponse(url=f"{base}{path}")


@router.get("/callback")
async def callback(request: Request) -> RedirectResponse:
    """Handle Google's OAuth2 callback.

    Validates state (CSRF), exchanges code for tokens server-side,
    stores encrypted refresh token, sets session, redirects to inbox.
    """
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")

    if error:
        logger.warning("OAuth error from Google: %s", error)
        return _frontend_redirect("/?error=oauth_denied")

    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state parameter")

    # CSRF validation
    session_state = request.session.get("oauth_state")
    if not session_state or not secrets.compare_digest(state, session_state):
        raise HTTPException(status_code=400, detail="Invalid OAuth state — possible CSRF attack")

    code_verifier = request.session.get("oauth_code_verifier")
    if not code_verifier:
        raise HTTPException(status_code=400, detail="Missing PKCE code_verifier in session")

    redirect_uri = request.session.pop("oauth_redirect_uri", None)

    # Clear PKCE state from session
    request.session.pop("oauth_state", None)
    request.session.pop("oauth_code_verifier", None)

    try:
        token_response = await exchange_code_for_tokens(code, code_verifier, redirect_uri=redirect_uri)
    except Exception as exc:
        logger.error("Token exchange failed: %s", exc)
        return _frontend_redirect("/?error=token_exchange_failed")

    access_token = token_response.get("access_token")
    refresh_token = token_response.get("refresh_token")
    expires_in = token_response.get("expires_in", 3600)
    scope = token_response.get("scope")

    if not access_token or not refresh_token:
        logger.error("Token response missing access_token or refresh_token")
        return _frontend_redirect("/?error=incomplete_token_response")

    # Fetch user profile
    try:
        userinfo = await get_userinfo(access_token)
    except Exception as exc:
        logger.error("Failed to fetch userinfo: %s", exc)
        return _frontend_redirect("/?error=userinfo_failed")

    user_email = userinfo.get("email")
    if not user_email:
        return _frontend_redirect("/?error=no_email")

    # Store tokens securely
    await store_tokens(
        user_email=user_email,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
        scope=scope,
    )

    # Persist user info in session
    request.session["user_email"] = user_email
    request.session["user_name"] = userinfo.get("name", "")
    request.session["user_picture"] = userinfo.get("picture", "")

    logger.info("OAuth flow complete for %s", user_email)
    return _frontend_redirect("/inbox")


@router.post("/logout")
async def logout(request: Request) -> JSONResponse:
    """Revoke Google tokens, clear session, return 200."""
    user_email = request.session.get("user_email")
    if user_email:
        try:
            from .token_store import get_valid_access_token
            try:
                access_token = await get_valid_access_token(user_email)
                await revoke_token(access_token)
            except Exception:
                pass  # Don't block logout if revocation fails

            await delete_tokens(user_email)
            logger.info("Logged out %s", user_email)
        except Exception as exc:
            logger.warning("Logout cleanup error: %s", exc)

    request.session.clear()
    return JSONResponse({"status": "logged_out"})


@router.get("/me")
async def me(request: Request) -> JSONResponse:
    """Return current session user info. 401 if not authenticated."""
    user_email = request.session.get("user_email")
    if not user_email:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return JSONResponse({
        "email": user_email,
        "name": request.session.get("user_name", ""),
        "picture": request.session.get("user_picture", ""),
    })
