"""Threat scores and audit log API endpoints."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select, and_, desc

from ..crypto import decrypt_token
from ..database import get_db, get_session_factory
from .models import AuditOverride, ThreatScore
from .quarantine import release_from_quarantine, quarantine_message, move_to_inbox, move_to_spam

logger = logging.getLogger(__name__)
router = APIRouter()


def _require_auth(request: Request) -> str:
    user_email = request.session.get("user_email")
    if not user_email:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user_email


def _score_to_dict(record: ThreatScore, include_headers: bool = False) -> dict:
    base = {
        "id": record.id,
        "message_id": record.message_id,
        "subject": record.subject,
        "sender": record.sender,
        "received_at": record.received_at.isoformat() if record.received_at else None,
        "analyzed_at": record.analyzed_at.isoformat() if record.analyzed_at else None,
        "spf": record.spf_result,
        "dkim": record.dkim_result,
        "dmarc": record.dmarc_result,
        "auth_score": record.auth_score,
        "geo_country": record.geo_country,
        "geo_asn": record.geo_asn,
        "geo_org": record.geo_org,
        "geo_lat": record.geo_lat,
        "geo_lon": record.geo_lon,
        "geo_mismatch": record.geo_mismatch,
        "geo_score": record.geo_score,
        "geo_hops": json.loads(record.geo_hops) if record.geo_hops else [],
        "llm_score": record.llm_score,
        "llm_threat_type": record.llm_threat_type,
        "llm_reasoning": json.loads(record.llm_reasoning) if record.llm_reasoning else [],
        "llm_suspicious_phrases": (
            json.loads(record.llm_suspicious_phrases)
            if record.llm_suspicious_phrases else []
        ),
        "urls_checked": json.loads(record.urls_checked) if record.urls_checked else [],
        "unsafe_urls": json.loads(record.unsafe_urls) if record.unsafe_urls else {},
        "url_score": record.url_score,
        "final_score": record.final_score,
        "severity": record.severity,
        "quarantined": record.quarantined,
        "detected_language": getattr(record, "detected_language", None),
        "language_code": getattr(record, "language_code", None),
    }
    if include_headers and record.raw_headers_encrypted:
        try:
            base["raw_headers"] = decrypt_token(record.raw_headers_encrypted)
        except Exception:
            base["raw_headers"] = "[decryption failed]"
    return base


@router.get("/")
async def list_threats(
    request: Request,
    severity: Optional[str] = Query(default=None, pattern="^(LOW|MEDIUM|HIGH)$"),
    sender: Optional[str] = Query(default=None),
    date_from: Optional[datetime] = Query(default=None),
    date_to: Optional[datetime] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, le=100),
) -> JSONResponse:
    """List threat score records with optional filters."""
    user_email = _require_auth(request)

    filters = [ThreatScore.user_email == user_email]
    if severity:
        filters.append(ThreatScore.severity == severity)
    if sender:
        filters.append(ThreatScore.sender.ilike(f"%{sender}%"))
    if date_from:
        filters.append(ThreatScore.analyzed_at >= date_from)
    if date_to:
        filters.append(ThreatScore.analyzed_at <= date_to)

    offset = (page - 1) * page_size

    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(ThreatScore)
            .where(and_(*filters))
            .order_by(desc(ThreatScore.analyzed_at))
            .offset(offset)
            .limit(page_size)
        )
        records = result.scalars().all()

        # Count total
        from sqlalchemy import func
        count_result = await session.execute(
            select(func.count(ThreatScore.id)).where(and_(*filters))
        )
        total = count_result.scalar() or 0

    return JSONResponse({
        "threats": [_score_to_dict(r) for r in records],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size,
    })


@router.get("/{threat_id}")
async def get_threat(
    request: Request,
    threat_id: str,
    include_headers: bool = Query(default=False),
) -> JSONResponse:
    """Get a single threat record with full forensic detail."""
    user_email = _require_auth(request)

    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(ThreatScore).where(
                ThreatScore.id == threat_id,
                ThreatScore.user_email == user_email,
            )
        )
        record = result.scalar_one_or_none()

    if not record:
        raise HTTPException(status_code=404, detail="Threat record not found")

    # Include overrides
    factory = get_session_factory()
    async with factory() as session:
        overrides_result = await session.execute(
            select(AuditOverride)
            .where(AuditOverride.threat_score_id == threat_id)
            .order_by(AuditOverride.override_at)
        )
        overrides = overrides_result.scalars().all()

    data = _score_to_dict(record, include_headers=include_headers)
    data["overrides"] = [
        {
            "id": o.id,
            "action": o.action,
            "reason": o.reason,
            "override_at": o.override_at.isoformat(),
        }
        for o in overrides
    ]
    return JSONResponse(data)


class OverrideRequest(BaseModel):
    action: str  # "release", "confirm", "move_inbox", "move_spam", "inbox", "spam"
    reason: Optional[str] = None
    destination_folder: Optional[str] = None  # "inbox" | "spam"


@router.post("/{threat_id}/override")
async def override_threat(
    request: Request,
    threat_id: str,
    body: OverrideRequest,
) -> JSONResponse:
    """Record a user override and move email to inbox or spam folder."""
    user_email = _require_auth(request)

    valid_actions = ("release", "confirm", "move_inbox", "move_spam", "inbox", "spam")
    if body.action not in valid_actions:
        raise HTTPException(status_code=400, detail=f"action must be one of: {', '.join(valid_actions)}")

    # Determine target folder
    dest_folder = (body.destination_folder or "").lower()
    if not dest_folder:
        if body.action in ("release", "move_inbox", "inbox"):
            dest_folder = "inbox"
        elif body.action in ("confirm", "move_spam", "spam"):
            dest_folder = "spam"
        else:
            dest_folder = "inbox"

    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(
            select(ThreatScore).where(
                ThreatScore.id == threat_id,
                ThreatScore.user_email == user_email,
            )
        )
        record = result.scalar_one_or_none()

        if not record:
            raise HTTPException(status_code=404, detail="Threat record not found")

        # Update quarantine state on record
        if dest_folder == "inbox":
            record.quarantined = False
        elif dest_folder == "spam":
            record.quarantined = True

        action_label = "release" if dest_folder == "inbox" else "confirm"
        reason_label = (
            f"[{dest_folder.upper()}] {body.reason}" if body.reason else f"Moved to {dest_folder.upper()}"
        )
        # Log the override (append-only)
        override = AuditOverride(
            threat_score_id=threat_id,
            user_email=user_email,
            action=body.action if body.action in ("release", "confirm") else action_label,
            reason=reason_label,
            override_at=datetime.now(timezone.utc),
        )
        session.add(override)
        await session.commit()

    logger.info(
        "Override: user=%s threat=%s action=%s dest=%s reason=%s",
        user_email, threat_id, body.action, dest_folder, body.reason,
    )

    # Perform folder move in Gmail
    folder_move_error = None
    try:
        if dest_folder == "inbox":
            await release_from_quarantine(user_email, record.message_id)
        elif dest_folder == "spam":
            await quarantine_message(user_email, record.message_id)
    except Exception as exc:
        logger.error("Failed to move email to %s for threat %s: %s", dest_folder, threat_id, exc)
        folder_move_error = str(exc)

    if folder_move_error:
        return JSONResponse(
            {
                "status": "override_logged",
                "folder_move": "failed",
                "destination_folder": dest_folder,
                "error": folder_move_error,
                "override_id": override.id,
            },
            status_code=207,
        )

    return JSONResponse({
        "status": "ok",
        "action": body.action,
        "destination_folder": dest_folder,
        "quarantined": record.quarantined,
        "override_id": override.id,
    })


@router.get("/stats/summary")
async def threat_stats(request: Request) -> JSONResponse:
    """Return threat score statistics for the dashboard."""
    user_email = _require_auth(request)

    factory = get_session_factory()
    async with factory() as session:
        from sqlalchemy import func
        result = await session.execute(
            select(
                ThreatScore.severity,
                func.count(ThreatScore.id).label("count"),
                func.avg(ThreatScore.final_score).label("avg_score"),
            )
            .where(ThreatScore.user_email == user_email)
            .group_by(ThreatScore.severity)
        )
        rows = result.all()

    stats = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "avg_scores": {}}
    for row in rows:
        stats[row.severity] = row.count
        stats["avg_scores"][row.severity] = round(row.avg_score or 0, 4)

    return JSONResponse(stats)
