"""Audit log data retention — purge records older than RETENTION_DAYS.

Privacy rationale:
- raw_headers_encrypted can contain third-party PII (email addresses, IPs
  of people who didn't consent to this service).
- Keeping it indefinitely is a growing liability.
- Default: nullify raw_headers_encrypted after 30 days, hard-delete full
  ThreatScore records (including overrides) after 90 days.

Purge strategy:
  Phase 1 (30d): Null out raw_headers_encrypted column — removes most PII
                 while preserving the threat score for auditing.
  Phase 2 (90d): Hard-delete the entire ThreatScore record and its overrides.
                 (ondelete="RESTRICT" on AuditOverride is changed to CASCADE
                 in practice via SQLAlchemy delete.)
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select, update

from ..config import get_settings
from ..database import get_session_factory
from .models import AuditOverride, ThreatScore

logger = logging.getLogger(__name__)


async def purge_old_records() -> dict[str, int]:
    """Execute the two-phase retention purge.

    Returns:
        dict with counts of records in each purge phase.
    """
    settings = get_settings()
    now = datetime.now(timezone.utc)

    # Phase 1: Null out raw headers after RETENTION_HEADERS_DAYS
    headers_cutoff = now - timedelta(days=settings.RETENTION_HEADERS_DAYS)
    # Phase 2: Hard-delete full records after RETENTION_DELETE_DAYS
    delete_cutoff = now - timedelta(days=settings.RETENTION_DELETE_DAYS)

    factory = get_session_factory()
    async with factory() as session:
        # Phase 1 — strip raw headers (remove PII from old records)
        phase1_result = await session.execute(
            update(ThreatScore)
            .where(
                ThreatScore.analyzed_at < headers_cutoff,
                ThreatScore.raw_headers_encrypted.is_not(None),
            )
            .values(raw_headers_encrypted=None)
        )
        phase1_count = phase1_result.rowcount

        # Phase 2 — delete overrides first (FK constraint), then scores
        expired_ids_select = select(ThreatScore.id).where(
            ThreatScore.analyzed_at < delete_cutoff
        )
        subq = await session.execute(
            delete(AuditOverride).where(
                AuditOverride.threat_score_id.in_(expired_ids_select)
            )
        )
        overrides_deleted = subq.rowcount

        phase2_result = await session.execute(
            delete(ThreatScore).where(ThreatScore.analyzed_at < delete_cutoff)
        )
        phase2_count = phase2_result.rowcount

        await session.commit()

    logger.info(
        "Retention purge: stripped headers from %d records (>%dd), "
        "deleted %d records + %d overrides (>%dd)",
        phase1_count, settings.RETENTION_HEADERS_DAYS,
        phase2_count, overrides_deleted, settings.RETENTION_DELETE_DAYS,
    )

    return {
        "headers_nulled": phase1_count,
        "records_deleted": phase2_count,
        "overrides_deleted": overrides_deleted,
    }


async def schedule_retention_purge() -> None:
    """Background task: run the retention purge once every 24 hours."""
    while True:
        await asyncio.sleep(24 * 3600)  # Wait 24h before first purge
        try:
            await purge_old_records()
        except Exception as exc:
            logger.error("Retention purge failed: %s", exc)
