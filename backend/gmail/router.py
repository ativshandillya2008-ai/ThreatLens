"""Gmail API proxy endpoints."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from ..database import get_session_factory
from ..threats.models import ThreatScore
from .client import GmailClient
from .pubsub import setup_watch

logger = logging.getLogger(__name__)
router = APIRouter()

# Active scanning tracker: set of (user_email, message_id)
_scanning_ids: set[tuple[str, str]] = set()
_scan_semaphore = asyncio.Semaphore(3)


async def _scan_message_worker(user_email: str, message_id: str) -> None:
    """Worker task to execute threat pipeline for a single message with concurrency limit."""
    key = (user_email, message_id)
    if key in _scanning_ids:
        return
    _scanning_ids.add(key)
    try:
        async with _scan_semaphore:
            from ..pipeline.runner import run_pipeline
            await run_pipeline(user_email=user_email, message_id=message_id)
    except Exception as exc:
        logger.error("Background scan failed for message %s: %s", message_id, exc)
    finally:
        _scanning_ids.discard(key)


async def _scan_unscored_batch(user_email: str, message_ids: list[str]) -> None:
    """Run pipeline concurrently for a batch of message IDs."""
    tasks = [_scan_message_worker(user_email, mid) for mid in message_ids]
    await asyncio.gather(*tasks, return_exceptions=True)


def _require_auth(request: Request) -> str:
    """Extract user_email from session or raise 401."""
    user_email = request.session.get("user_email")
    if not user_email:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user_email


@router.get("/setup-watch")
async def trigger_watch_setup(request: Request) -> JSONResponse:
    """Manually trigger Gmail watch setup for the current user."""
    user_email = _require_auth(request)
    result = await setup_watch(user_email)
    return JSONResponse({"status": "ok", "watch": result})


@router.get("/messages")
async def list_messages(
    request: Request,
    background_tasks: BackgroundTasks,
    q: str = Query(default="", description="Gmail search query"),
    max_results: int = Query(default=25, le=100),
    page_token: Optional[str] = Query(default=None),
    auto_scan: bool = Query(default=True, description="Auto-scan unscored messages in background"),
) -> JSONResponse:
    """List Gmail messages, enriched with threat scores from the DB.
    
    If auto_scan is True, any unscored messages found in this batch are
    automatically queued for background AI threat scanning.
    """
    user_email = _require_auth(request)

    async with GmailClient(user_email) as client:
        data = await client.list_messages(
            query=q, max_results=max_results, page_token=page_token
        )

    messages = data.get("messages", [])
    if not messages:
        return JSONResponse({
            "messages": [],
            "nextPageToken": data.get("nextPageToken"),
            "scanning": False,
            "unscoredCount": 0,
        })

    message_ids = [m["id"] for m in messages]

    # Fetch threat scores from DB for these message IDs
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(ThreatScore).where(
                ThreatScore.message_id.in_(message_ids),
                ThreatScore.user_email == user_email,
            )
        )
        score_records = {r.message_id: r for r in result.scalars().all()}

    # Trigger background scan for any unscored messages
    unscored_ids = [mid for mid in message_ids if mid not in score_records]
    if auto_scan and unscored_ids:
        to_queue = [mid for mid in unscored_ids if (user_email, mid) not in _scanning_ids]
        if to_queue:
            logger.info("Queuing background scan for %d unscored messages", len(to_queue))
            background_tasks.add_task(_scan_unscored_batch, user_email, to_queue)

    is_currently_scanning = any((user_email, mid) in _scanning_ids for mid in message_ids) or bool(unscored_ids and auto_scan)

    # Fetch metadata for each message
    enriched = []
    async with GmailClient(user_email) as client:
        for msg in messages:
            try:
                full = await client.get_message(msg["id"], format="metadata")
                headers = {}
                for h in full.get("payload", {}).get("headers", []):
                    headers[h["name"].lower()] = h["value"]

                score_record = score_records.get(msg["id"])
                enriched.append({
                    "id": msg["id"],
                    "threadId": msg.get("threadId"),
                    "subject": headers.get("subject", "(no subject)"),
                    "from": headers.get("from", ""),
                    "date": headers.get("date", ""),
                    "snippet": full.get("snippet", ""),
                    "labelIds": full.get("labelIds", []),
                    "threat": {
                        "score": score_record.final_score if score_record else None,
                        "severity": score_record.severity if score_record else None,
                        "analyzed": score_record is not None,
                        "threat_id": str(score_record.id) if score_record else None,
                        "geo_lat": score_record.geo_lat if score_record else None,
                        "geo_lon": score_record.geo_lon if score_record else None,
                        "geo_country": score_record.geo_country if score_record else None,
                        "geo_org": score_record.geo_org if score_record else None,
                        "geo_city": (
                            json.loads(score_record.geo_hops)[0].get("city")
                            if score_record and score_record.geo_hops and json.loads(score_record.geo_hops)
                            else None
                        ) if score_record else None,
                        "ip": (
                            json.loads(score_record.geo_hops)[0].get("ip")
                            if score_record and score_record.geo_hops and json.loads(score_record.geo_hops)
                            else None
                        ) if score_record else None,
                    },
                })
            except Exception as exc:
                logger.warning("Failed to fetch message %s metadata: %s", msg["id"], exc)

    return JSONResponse({
        "messages": enriched,
        "nextPageToken": data.get("nextPageToken"),
        "scanning": is_currently_scanning,
        "unscoredCount": len(unscored_ids),
    })


@router.get("/messages/{message_id}")
async def get_message(request: Request, message_id: str) -> JSONResponse:
    """Fetch complete email content plus associated threat score if already analyzed."""
    user_email = _require_auth(request)

    async with GmailClient(user_email) as client:
        data = await client.get_message(message_id, format="full")

    # Look up ThreatScore by message_id
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(ThreatScore).where(
                ThreatScore.message_id == message_id,
                ThreatScore.user_email == user_email,
            )
        )
        score_record = result.scalars().first()

    # If message has never been scored, run the pipeline on-demand now
    if not score_record:
        try:
            from ..pipeline.runner import run_pipeline
            logger.info("On-demand scan triggered for message %s", message_id)
            score_record = await run_pipeline(user_email=user_email, message_id=message_id)
        except Exception as exc:
            logger.error("On-demand scan failed for %s: %s", message_id, exc)

    threat_data = None
    if score_record:
        import json
        hops = json.loads(score_record.geo_hops) if score_record.geo_hops else []
        threat_data = {
            "id": str(score_record.id),
            "message_id": score_record.message_id,
            "subject": score_record.subject,
            "sender": score_record.sender,
            "final_score": score_record.final_score,
            "severity": score_record.severity,
            "spf": score_record.spf_result,
            "dkim": score_record.dkim_result,
            "dmarc": score_record.dmarc_result,
            "auth_score": score_record.auth_score,
            "geo_country": score_record.geo_country,
            "geo_asn": score_record.geo_asn,
            "geo_org": score_record.geo_org,
            "geo_lat": score_record.geo_lat or (hops[0].get("lat") if hops else 37.0902),
            "geo_lon": score_record.geo_lon or (hops[0].get("lon") if hops else -95.7129),
            "geo_mismatch": score_record.geo_mismatch,
            "geo_score": score_record.geo_score,
            "geo_hops": hops,
            "llm_score": score_record.llm_score,
            "llm_threat_type": score_record.llm_threat_type,
            "llm_reasoning": json.loads(score_record.llm_reasoning) if score_record.llm_reasoning else [],
            "llm_suspicious_phrases": (
                json.loads(score_record.llm_suspicious_phrases)
                if score_record.llm_suspicious_phrases else []
            ),
            "urls_checked": json.loads(score_record.urls_checked) if score_record.urls_checked else [],
            "unsafe_urls": json.loads(score_record.unsafe_urls) if score_record.unsafe_urls else {},
            "url_score": score_record.url_score,
            "quarantined": score_record.quarantined,
            "analyzed_at": score_record.analyzed_at.isoformat() if score_record.analyzed_at else None,
        }

    return JSONResponse({"message": data, "threat": threat_data})


@router.post("/scan")
async def scan_inbox_messages(
    request: Request,
    background_tasks: BackgroundTasks,
    max_results: int = Query(default=25, le=100),
) -> JSONResponse:
    """Explicitly trigger AI threat scanning for unscored inbox messages."""
    user_email = _require_auth(request)

    async with GmailClient(user_email) as client:
        data = await client.list_messages(max_results=max_results)

    messages = data.get("messages", [])
    if not messages:
        return JSONResponse({"status": "no_messages", "scanned": 0, "unscored_remaining": 0})

    message_ids = [m["id"] for m in messages]

    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(ThreatScore.message_id).where(
                ThreatScore.message_id.in_(message_ids),
                ThreatScore.user_email == user_email,
            )
        )
        scored_ids = set(result.scalars().all())

    unscored_ids = [mid for mid in message_ids if mid not in scored_ids]
    to_queue = [mid for mid in unscored_ids if (user_email, mid) not in _scanning_ids]
    if to_queue:
        logger.info("Manual scan trigger: queuing %d messages for %s", len(to_queue), user_email)
        background_tasks.add_task(_scan_unscored_batch, user_email, to_queue)

    return JSONResponse({
        "status": "scanning" if (to_queue or unscored_ids) else "complete",
        "queued": len(to_queue),
        "unscored_count": len(unscored_ids),
        "already_scored": len(scored_ids),
        "total": len(message_ids),
    })


@router.get("/scan-status")
async def get_scan_status(request: Request) -> JSONResponse:
    """Return whether scanning is currently active for the current user."""
    user_email = _require_auth(request)
    active = [mid for (u, mid) in _scanning_ids if u == user_email]
    return JSONResponse({
        "scanning": len(active) > 0,
        "active_count": len(active),
    })
