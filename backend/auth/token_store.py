"""Encrypted OAuth token persistence layer.

Refresh tokens are encrypted with Fernet before storage.
Access tokens are NEVER persisted — they live only in memory.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, DateTime, String, Text
from sqlalchemy.ext.asyncio import AsyncSession

from ..crypto import decrypt_token, encrypt_token
from ..database import Base, get_session_factory
from .oauth import refresh_access_token

logger = logging.getLogger(__name__)

# In-memory access token cache: {user_email: (access_token, expires_at)}
_access_token_cache: dict[str, tuple[str, datetime]] = {}


class StoredToken(Base):
    """Persisted (encrypted) OAuth token record."""
    __tablename__ = "stored_tokens"

    user_email = Column(String(255), primary_key=True, index=True)
    encrypted_refresh_token = Column(Text, nullable=False)
    token_type = Column(String(32), default="Bearer")
    scope = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


async def store_tokens(
    user_email: str,
    access_token: str,
    refresh_token: str,
    expires_in: int,
    scope: Optional[str] = None,
) -> None:
    """Encrypt and persist the refresh token; cache the access token in memory."""
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=expires_in - 60)  # 60s buffer

    # Cache access token in memory (never written to disk)
    _access_token_cache[user_email] = (access_token, expires_at)

    # Encrypt and persist refresh token
    encrypted_rt = encrypt_token(refresh_token)
    factory = get_session_factory()
    async with factory() as session:
        existing = await session.get(StoredToken, user_email)
        if existing:
            existing.encrypted_refresh_token = encrypted_rt
            existing.scope = scope
            existing.updated_at = now
        else:
            session.add(StoredToken(
                user_email=user_email,
                encrypted_refresh_token=encrypted_rt,
                scope=scope,
            ))
        await session.commit()
    logger.info("Stored tokens for %s", user_email)


async def has_stored_refresh_token(user_email: str) -> bool:
    """Check if a stored refresh token exists in DB for this user."""
    factory = get_session_factory()
    async with factory() as session:
        record = await session.get(StoredToken, user_email)
        return record is not None and bool(record.encrypted_refresh_token)


def cache_access_token(user_email: str, access_token: str, expires_in: int) -> None:
    """Cache the active access token in memory."""
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=expires_in - 60)
    _access_token_cache[user_email] = (access_token, expires_at)



async def get_valid_access_token(user_email: str) -> str:
    """Return a valid access token, refreshing if expired.

    Raises:
        ValueError: If no token record exists (user not authenticated)
        RuntimeError: If token refresh fails
    """
    from datetime import timedelta
    now = datetime.now(timezone.utc)

    # Check in-memory cache first
    if user_email in _access_token_cache:
        access_token, expires_at = _access_token_cache[user_email]
        if now < expires_at:
            return access_token

    # Fetch encrypted refresh token from DB
    factory = get_session_factory()
    async with factory() as session:
        record = await session.get(StoredToken, user_email)

    if not record:
        raise ValueError(f"No token record for {user_email}. User must re-authenticate.")

    # Decrypt refresh token and exchange for new access token
    try:
        refresh_token = decrypt_token(record.encrypted_refresh_token)
        token_response = await refresh_access_token(refresh_token)
    except Exception as exc:
        logger.error("Token refresh failed for %s: %s", user_email, exc)
        _access_token_cache.pop(user_email, None)
        raise RuntimeError(
            f"Token refresh failed for {user_email}. User must re-authenticate."
        ) from exc

    new_access_token = token_response["access_token"]
    expires_in = token_response.get("expires_in", 3600)
    expires_at = now + timedelta(seconds=expires_in - 60)

    # Update in-memory cache
    _access_token_cache[user_email] = (new_access_token, expires_at)

    # If Google issued a new refresh token, re-encrypt and store it
    if "refresh_token" in token_response:
        new_rt = token_response["refresh_token"]
        encrypted_rt = encrypt_token(new_rt)
        factory = get_session_factory()
        async with factory() as session:
            record = await session.get(StoredToken, user_email)
            if record:
                record.encrypted_refresh_token = encrypted_rt
                record.updated_at = now
                await session.commit()
        logger.info("Refreshed and stored new refresh token for %s", user_email)

    return new_access_token


async def delete_tokens(user_email: str) -> None:
    """Remove all stored tokens for a user (called on logout)."""
    _access_token_cache.pop(user_email, None)
    factory = get_session_factory()
    async with factory() as session:
        record = await session.get(StoredToken, user_email)
        if record:
            await session.delete(record)
            await session.commit()
    logger.info("Deleted tokens for %s", user_email)
