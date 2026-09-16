"""Threat pipeline orchestrator.

Runs all scoring stages and writes an append-only audit record.
"""
from __future__ import annotations

import asyncio
import email
import json
import logging
from datetime import datetime, timezone
from email.message import Message
from typing import Any, Optional

from ..config import get_settings
from ..database import get_session_factory
from .geoip import score_geoip
from .llm_analyzer import score_llm
from .safe_browsing import score_safe_browsing
from .spf_dkim_dmarc import score_spf_dkim_dmarc

logger = logging.getLogger(__name__)


def _compute_severity(final_score: float) -> str:
    settings = get_settings()
    if final_score >= settings.THRESHOLD_HIGH:
        return "HIGH"
    elif final_score >= settings.THRESHOLD_MEDIUM:
        return "MEDIUM"
    return "LOW"


def _get_header(msg: Message, name: str, default: str = "") -> str:
    return msg.get(name, default) or default


async def run_pipeline(
    user_email: str,
    message_id: str,
    raw_bytes: Optional[bytes] = None,
    label_ids: Optional[list[str]] = None,
    force_rescore: bool = False,
) -> Any:
    """Run the full threat scoring pipeline for a Gmail message.

    Args:
        user_email: The Gmail account owner
        message_id: Gmail message ID
        raw_bytes: Optional pre-fetched raw RFC2822 bytes
        label_ids: Optional Gmail label IDs (e.g. ['SPAM', 'UNREAD'])
        force_rescore: If True, re-analyze even if already analyzed

    Returns:
        The created or updated ThreatScore DB record, or None if skipped/failed
    """
    import base64
    from ..threats.models import ThreatScore
    from ..threats.quarantine import ensure_quarantine_label, quarantine_message
    from ..gmail.client import GmailClient
    from ..crypto import encrypt_token

    settings = get_settings()

    logger.info("Pipeline start: user=%s message=%s", user_email, message_id)
    started_at = datetime.now(timezone.utc)

    # ── 1. Check if already analyzed ────────────────────────────────────────
    factory = get_session_factory()
    existing_record = None
    async with factory() as session:
        from sqlalchemy import select
        existing = await session.execute(
            select(ThreatScore).where(
                ThreatScore.message_id == message_id,
                ThreatScore.user_email == user_email,
            )
        )
        existing_record = existing.scalars().first()
        if existing_record and not force_rescore:
            # Check if this was a degraded scan (0.0 with empty reasoning from rate limits)
            is_degraded = (
                existing_record.final_score == 0.0
                and (not existing_record.llm_reasoning or existing_record.llm_reasoning in ('[]', 'null', ''))
            )
            if not is_degraded:
                logger.info("Message %s already analyzed, skipping", message_id)
                return existing_record
            logger.info("Message %s has degraded/empty 0.0 score, re-analyzing", message_id)

    # ── 2. Fetch raw message and labels ───────────────────────────────────────
    if raw_bytes is None or label_ids is None:
        try:
            async with GmailClient(user_email) as client:
                if raw_bytes is None:
                    raw_data = await client._request("GET", f"/messages/{message_id}", params={"format": "raw"})
                    raw_b64 = raw_data.get("raw", "")
                    padded = raw_b64 + "==" * ((-len(raw_b64)) % 4)
                    raw_bytes = base64.urlsafe_b64decode(padded)
                    if label_ids is None:
                        label_ids = raw_data.get("labelIds", [])
                elif label_ids is None:
                    meta = await client.get_message(message_id, format="minimal")
                    label_ids = meta.get("labelIds", [])
        except Exception as exc:
            logger.error("Failed to fetch message %s: %s", message_id, exc)
            if raw_bytes is None:
                return None

    msg: Message = email.message_from_bytes(raw_bytes)

    subject = _get_header(msg, "Subject", "(no subject)")
    sender = _get_header(msg, "From")
    date_str = _get_header(msg, "Date")

    try:
        from email.utils import parsedate_to_datetime
        received_at = parsedate_to_datetime(date_str) if date_str else started_at
    except Exception:
        received_at = started_at

    # ── 3. Run all pipeline stages concurrently ──────────────────────────────
    try:
        (
            auth_result,
            geo_result,
            llm_result,
            url_result,
        ) = await asyncio.gather(
            score_spf_dkim_dmarc(msg),
            score_geoip(msg),
            score_llm(msg),
            score_safe_browsing(msg),
            return_exceptions=False,
        )
    except Exception as exc:
        logger.error("Pipeline stage error for %s: %s", message_id, exc)
        return None

    # ── 4. Compute weighted final score with dominant threat escalation ──────
    weighted_score = (
        auth_result.score * settings.WEIGHT_SPF_DKIM_DMARC
        + geo_result.score * settings.WEIGHT_GEOIP
        + llm_result.score * settings.WEIGHT_LLM
        + url_result.score * settings.WEIGHT_SAFE_BROWSING
    )

    # Check if message is classified as SPAM by Gmail
    is_spam_quarantined = bool(label_ids and any(l.upper() in ("SPAM", "TRASH") for l in label_ids))

    # Dominant threat escalation: a high-confidence threat in any individual vector
    # (LLM phishing/malware detection, malicious URLs, or severe spoofing) must not be
    # diluted below critical thresholds by zero scores in other vectors.
    escalated_score = weighted_score
    if url_result.score >= 1.0:
        escalated_score = max(escalated_score, 0.85)

    is_malicious_type = llm_result.threat_type in (
        "phishing", "social_engineering", "malware_lure"
    )
    if llm_result.score >= 0.70 or (is_malicious_type and llm_result.score >= 0.60):
        # AI high-confidence threat -> HIGH
        escalated_score = max(escalated_score, max(0.75, llm_result.score))
    elif llm_result.score >= 0.40 or is_malicious_type or auth_result.score >= 0.70:
        # AI moderate threat / suspicious indicators / auth failure -> MEDIUM
        escalated_score = max(escalated_score, max(0.45, llm_result.score * 0.8))

    final_reasoning = list(llm_result.reasoning)

    # Gmail SPAM integration: An email placed in Gmail's Spam vault has already been
    # flagged by Google's anti-abuse filters. It must NEVER be classified as Safe (LOW).
    if is_spam_quarantined:
        if escalated_score >= 0.70:
            escalated_score = max(escalated_score, 0.80)
        else:
            escalated_score = max(escalated_score, 0.50)

        spam_note = "Isolated in Gmail Spam & Abuse Quarantine (SPAM label present)."
        if spam_note not in final_reasoning:
            final_reasoning.insert(0, spam_note)

    final_score = round(min(escalated_score, 1.0), 4)
    severity = _compute_severity(final_score)

    logger.info(
        "Pipeline result: message=%s score=%.4f severity=%s (is_spam=%s) "
        "(auth=%.2f geo=%.2f llm=%.2f url=%.2f)",
        message_id, final_score, severity, is_spam_quarantined,
        auth_result.score, geo_result.score, llm_result.score, url_result.score,
    )

    # ── 5. Encrypt raw headers for forensic storage ──────────────────────────
    raw_headers = ""
    try:
        header_lines = [f"{key}: {value}" for key, value in msg.items()]
        raw_headers = encrypt_token("\n".join(header_lines))
    except Exception as exc:
        logger.warning("Failed to encrypt raw headers: %s", exc)

    # ── 6. Write or update append-only audit record ───────────────────────────
    analyzed_at = datetime.now(timezone.utc)
    quarantined = severity in ("MEDIUM", "HIGH") or is_spam_quarantined

    from sqlalchemy import select, update

    async with factory() as session:
        if existing_record:
            await session.execute(
                update(ThreatScore)
                .where(
                    ThreatScore.message_id == message_id,
                    ThreatScore.user_email == user_email,
                )
                .values(
                    subject=subject,
                    sender=sender,
                    received_at=received_at,
                    analyzed_at=analyzed_at,
                    spf_result=auth_result.spf,
                    dkim_result=auth_result.dkim,
                    dmarc_result=auth_result.dmarc,
                    auth_score=auth_result.score,
                    geo_country=geo_result.primary_country,
                    geo_asn=geo_result.primary_asn,
                    geo_org=geo_result.primary_org,
                    geo_lat=geo_result.primary_lat,
                    geo_lon=geo_result.primary_lon,
                    geo_mismatch=geo_result.geo_mismatch,
                    geo_score=geo_result.score,
                    geo_hops=json.dumps(geo_result.geo_hops),
                    llm_score=llm_result.score,
                    llm_threat_type=llm_result.threat_type,
                    llm_reasoning=json.dumps(final_reasoning),
                    llm_suspicious_phrases=json.dumps(llm_result.suspicious_phrases),
                    urls_checked=json.dumps(url_result.urls_checked),
                    unsafe_urls=json.dumps(url_result.unsafe_urls),
                    url_score=url_result.score,
                    final_score=final_score,
                    severity=severity,
                    quarantined=quarantined,
                    raw_headers_encrypted=raw_headers,
                    detected_language=llm_result.detected_language,
                    language_code=llm_result.language_code,
                )
            )
            await session.commit()
            refreshed = await session.execute(
                select(ThreatScore).where(
                    ThreatScore.message_id == message_id,
                    ThreatScore.user_email == user_email,
                )
            )
            record = refreshed.scalars().first()
        else:
            record = ThreatScore(
                user_email=user_email,
                message_id=message_id,
                subject=subject,
                sender=sender,
                received_at=received_at,
                analyzed_at=analyzed_at,
                spf_result=auth_result.spf,
                dkim_result=auth_result.dkim,
                dmarc_result=auth_result.dmarc,
                auth_score=auth_result.score,
                geo_country=geo_result.primary_country,
                geo_asn=geo_result.primary_asn,
                geo_org=geo_result.primary_org,
                geo_lat=geo_result.primary_lat,
                geo_lon=geo_result.primary_lon,
                geo_mismatch=geo_result.geo_mismatch,
                geo_score=geo_result.score,
                geo_hops=json.dumps(geo_result.geo_hops),
                llm_score=llm_result.score,
                llm_threat_type=llm_result.threat_type,
                llm_reasoning=json.dumps(final_reasoning),
                llm_suspicious_phrases=json.dumps(llm_result.suspicious_phrases),
                urls_checked=json.dumps(url_result.urls_checked),
                unsafe_urls=json.dumps(url_result.unsafe_urls),
                url_score=url_result.score,
                final_score=final_score,
                severity=severity,
                quarantined=quarantined,
                raw_headers_encrypted=raw_headers,
                detected_language=llm_result.detected_language,
                language_code=llm_result.language_code,
            )
            session.add(record)
            await session.commit()
            await session.refresh(record)

    # ── 7. Apply quarantine label if needed ──────────────────────────────────
    if quarantined and not is_spam_quarantined:
        try:
            await ensure_quarantine_label(user_email)
            await quarantine_message(user_email, message_id)
            logger.info("Quarantined message %s (severity=%s)", message_id, severity)
        except Exception as exc:
            logger.error("Failed to quarantine message %s: %s", message_id, exc)

    logger.info(
        "Pipeline complete: message=%s took=%.2fs",
        message_id,
        (analyzed_at - started_at).total_seconds(),
    )
    return record
