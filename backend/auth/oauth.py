"""Google OAuth2 PKCE client using Authlib.

All token exchanges happen server-side. The client never sees the client_secret.
PKCE (S256 code challenge) is used to prevent authorization code interception.
"""
from __future__ import annotations

import hashlib
import os
import base64
from typing import Any, Optional

import httpx

from ..config import get_settings

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
GOOGLE_CERTS_URL = "https://www.googleapis.com/oauth2/v3/certs"


def generate_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE code_verifier and code_challenge (S256).

    Returns:
        (code_verifier, code_challenge)
    """
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return code_verifier, code_challenge


def build_authorization_url(state: str, code_challenge: str, redirect_uri: Optional[str] = None) -> str:
    """Build the Google OAuth2 authorization URL with PKCE."""
    settings = get_settings()
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": redirect_uri or settings.OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope": settings.OAUTH_SCOPES,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",   # Request refresh token
        "prompt": "consent",        # Always show consent to ensure refresh token
    }
    query = "&".join(f"{k}={v}" for k, v in params.items())
    return f"{GOOGLE_AUTH_URL}?{query}"


async def exchange_code_for_tokens(
    code: str, code_verifier: str, redirect_uri: Optional[str] = None
) -> dict[str, Any]:
    """Exchange authorization code for access + refresh tokens (server-side).

    Args:
        code: Authorization code from Google callback
        code_verifier: PKCE verifier matching the challenge sent
        redirect_uri: Optional redirect URI matching the one sent in auth request

    Returns:
        Token response dict from Google

    Raises:
        httpx.HTTPStatusError: If token exchange fails
    """
    settings = get_settings()
    async with httpx.AsyncClient() as client:
        response = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "redirect_uri": redirect_uri or settings.OAUTH_REDIRECT_URI,
                "grant_type": "authorization_code",
                "code_verifier": code_verifier,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15.0,
        )
        response.raise_for_status()
        return response.json()


async def refresh_access_token(refresh_token: str) -> dict[str, Any]:
    """Obtain a new access token using the stored refresh token.

    Args:
        refresh_token: Decrypted refresh token

    Returns:
        Token response dict (contains new access_token, may contain new refresh_token)

    Raises:
        httpx.HTTPStatusError: If refresh fails (e.g., token revoked)
    """
    settings = get_settings()
    async with httpx.AsyncClient() as client:
        response = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "refresh_token": refresh_token,
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "grant_type": "refresh_token",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15.0,
        )
        response.raise_for_status()
        return response.json()


async def revoke_token(token: str) -> None:
    """Revoke an access or refresh token at Google's revocation endpoint."""
    async with httpx.AsyncClient() as client:
        await client.post(
            GOOGLE_REVOKE_URL,
            params={"token": token},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10.0,
        )
        # Ignore errors — revocation is best-effort


async def get_userinfo(access_token: str) -> dict[str, Any]:
    """Fetch the authenticated user's profile from Google."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10.0,
        )
        response.raise_for_status()
        return response.json()
