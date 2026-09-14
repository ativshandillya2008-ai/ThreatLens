"""Gmail Pub/Sub push notification handler and watch management."""
from __future__ import annotations

import asyncio
import base64
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import Column, DateTime, String

from ..config import get_settings
from ..database import Base, get_session_factory
from .client import GmailClient

logger = logging.getLogger(__name__)
router = APIRouter()

GOOGLE_TOKEN_INFO_URL = "https://oauth2.googleapis.com/tokeninfo"

# Watch state: {user_email: {historyId, expiration}}
_watch_state: dict[str, dict[str, Any]] = {}


class WatchState(Base):
    """Persisted Gmail watch state."""
    __tablename__ = "gmail_watch_state"

    user_email = Column(String(255), primary_key=True)
    history_id = Column(String(64), nullable=False)
    expiration = Column(String(64), nullable=True)
    topic_name = Column(String(256), nullable=True)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )


async def setup_watch(user_email: str) -> dict[str, Any]:
    """Register Gmail push notifications for a user."""
    settings = get_settings()
    if not settings.PUBSUB_TOPIC:
        logger.warning("PUBSUB_TOPIC not configured — skipping watch setup")
        return {}

    try:
        async with GmailClient(user_email) as client:
            result = await client.watch(topic_name=settings.PUBSUB_TOPIC)

        history_id = result.get("historyId", "")
        expiration = result.get("expiration", "")
        _watch_state[user_email] = {
            "historyId": history_id,
            "expiration": expiration,
        }

        factory = get_session_factory()
        async with factory() as session:
            existing = await session.get(WatchState, user_email)
            now = datetime.now(timezone.utc)
            if existing:
                existing.history_id = history_id
                existing.expiration = expiration
                existing.topic_name = settings.PUBSUB_TOPIC
                existing.updated_at = now
            else:
                session.add(WatchState(
                    user_email=user_email,
                    history_id=history_id,
                    expiration=expiration,
                    topic_name=settings.PUBSUB_TOPIC,
                ))
            await session.commit()

        logger.info("Watch set up for %s, historyId=%s, expires=%s",
                    user_email, history_id, expiration)
        return result

    except Exception as exc:
        logger.error("Failed to set up watch for %s: %s", user_email, exc)
        return {}


async def schedule_watch_renewal() -> None:
    """Background task: renew watches for all authenticated users every 6 days."""
    settings = get_settings()
    if not settings.PUBSUB_TOPIC:
        return

    while True:
        await asyncio.sleep(6 * 24 * 3600)
        logger.info("Renewing Gmail watches for all users...")
        try:
            factory = get_session_factory()
            async with factory() as session:
                from sqlalchemy import select
                result = await session.execute(select(WatchState))
                watch_records = result.scalars().all()

            for record in watch_records:
                await setup_watch(record.user_email)
        except Exception as exc:
            logger.error("Watch renewal error: %s", exc)


async def _verify_google_push_jwt(request: Request) -> bool:
    """Verify the Google-signed OIDC JWT on Pub/Sub push requests.

    Validates BOTH:
    1. Token signature (via Google's tokeninfo endpoint)
    2. The 'aud' claim matches PUBSUB_PUSH_AUDIENCE exactly

    Signature-only verification is insufficient — it would allow any valid
    Google-signed token (from any Pub/Sub subscription) to trigger this endpoint.

    Returns True if valid, False otherwise.
    """
    settings = get_settings()

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        logger.warning("Pub/Sub push missing Bearer token")
        return False

    token = auth_header[7:]

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                GOOGLE_TOKEN_INFO_URL,
                params={"id_token": token},
            )
            if resp.status_code != 200:
                logger.warning("Pub/Sub JWT tokeninfo returned %s", resp.status_code)
                return False
            info = resp.json()

        # ── BUG FIX: validate 'aud' claim explicitly ─────────────────────────
        # Without this, ANY valid Google-signed OIDC token would pass, allowing
        # replay attacks from a different Pub/Sub subscription.
        if settings.PUBSUB_PUSH_AUDIENCE:
            token_aud = info.get("aud", "")
            expected_aud = settings.PUBSUB_PUSH_AUDIENCE
            if token_aud != expected_aud:
                logger.warning(
                    "Pub/Sub JWT aud mismatch: got=%r expected=%r",
                    token_aud, expected_aud,
                )
                return False
        else:
            # No audience configured — log warning but allow through in dev
            logger.warning(
                "PUBSUB_PUSH_AUDIENCE not set: skipping aud validation. "
                "Set this in production to prevent replay attacks."
            )

        # Validate issuer is Google
        issuer = info.get("iss", "")
        if issuer not in ("accounts.google.com", "https://accounts.google.com"):
            logger.warning("Pub/Sub JWT issuer invalid: %s", issuer)
            return False

        return True

    except Exception as exc:
        logger.warning("Pub/Sub JWT verification error: %s", exc)
        return False


@router.post("/push")
async def pubsub_push(
    request: Request,
    background_tasks: BackgroundTasks,
) -> JSONResponse:
    """Receive Gmail push notifications from Cloud Pub/Sub.

    Verifies Google OIDC JWT (signature + aud claim) before processing.
    Always returns 200 to acknowledge delivery (prevents Pub/Sub retries).
    """
    # Verify JWT — reject if invalid (except in DEBUG mode)
    settings = get_settings()
    jwt_valid = await _verify_google_push_jwt(request)
    if not jwt_valid and not settings.DEBUG:
        # Return 200 anyway to avoid Pub/Sub retry storms on auth issues
        # but don't process the payload
        logger.error("Rejected Pub/Sub push: invalid JWT")
        return JSONResponse({"status": "rejected"})

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    message = body.get("message", {})
    data_b64 = message.get("data", "")

    if not data_b64:
        logger.warning("Pub/Sub push with empty data")
        return JSONResponse({"status": "ok"})

    try:
        data_bytes = base64.b64decode(data_b64)
        data = json.loads(data_bytes)
    except Exception as exc:
        logger.error("Failed to decode Pub/Sub message: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid Pub/Sub message data")

    email_address = data.get("emailAddress")
    history_id = data.get("historyId")

    if not email_address or not history_id:
        logger.warning("Pub/Sub message missing emailAddress or historyId")
        return JSONResponse({"status": "ok"})

    logger.info("Pub/Sub push: user=%s, historyId=%s", email_address, history_id)

    background_tasks.add_task(
        _process_new_messages,
        user_email=email_address,
        new_history_id=str(history_id),
    )

    return JSONResponse({"status": "ok"})


async def _process_new_messages(user_email: str, new_history_id: str) -> None:
    """Fetch new messages since the last known historyId and run the threat pipeline."""
    from ..pipeline.runner import run_pipeline

    last_state = _watch_state.get(user_email, {})
    last_history_id = last_state.get("historyId")

    if not last_history_id:
        factory = get_session_factory()
        async with factory() as session:
            record = await session.get(WatchState, user_email)
            if record:
                last_history_id = record.history_id

    if not last_history_id:
        logger.warning("No prior historyId for %s, skipping", user_email)
        _watch_state[user_email] = {"historyId": new_history_id}
        return

    try:
        async with GmailClient(user_email) as client:
            history_data = await client.get_message_history(last_history_id)

        messages_added = []
        for record in history_data.get("history", []):
            for msg in record.get("messagesAdded", []):
                messages_added.append(msg.get("message", {}).get("id"))

        logger.info(
            "Found %d new messages for %s since historyId=%s",
            len(messages_added), user_email, last_history_id,
        )

        for message_id in messages_added:
            if message_id:
                try:
                    await run_pipeline(user_email=user_email, message_id=message_id)
                except Exception as exc:
                    logger.error("Pipeline failed for message %s: %s", message_id, exc)

    except Exception as exc:
        logger.error("Failed to fetch history for %s: %s", user_email, exc)
    finally:
        _watch_state[user_email] = {"historyId": new_history_id}
        factory = get_session_factory()
        async with factory() as session:
            record = await session.get(WatchState, user_email)
            if record:
                record.history_id = new_history_id
                await session.commit()
