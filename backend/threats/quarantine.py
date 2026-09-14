"""Gmail quarantine label management.

Creates and manages the '⚠️ Quarantine' Gmail label.
All operations are idempotent.
"""
from __future__ import annotations

import logging
from typing import Optional

from ..gmail.client import GmailClient

logger = logging.getLogger(__name__)

QUARANTINE_LABEL_NAME = "⚠️ Quarantine"
QUARANTINE_BG_COLOR = "#cc0000"  # Red
QUARANTINE_TEXT_COLOR = "#ffffff"  # White

# In-memory label ID cache: {user_email: label_id}
_label_id_cache: dict[str, str] = {}


async def ensure_quarantine_label(user_email: str) -> str:
    """Get or create the Quarantine label for the user.

    Returns:
        The Gmail label ID.
    """
    if user_email in _label_id_cache:
        return _label_id_cache[user_email]

    async with GmailClient(user_email) as client:
        # Check if label already exists
        labels = await client.list_labels()
        for label in labels:
            if label.get("name") == QUARANTINE_LABEL_NAME:
                label_id = label["id"]
                _label_id_cache[user_email] = label_id
                logger.info("Found existing Quarantine label: %s", label_id)
                return label_id

        # Create the label
        new_label = await client.create_label(
            name=QUARANTINE_LABEL_NAME,
            background_color=QUARANTINE_BG_COLOR,
            text_color=QUARANTINE_TEXT_COLOR,
        )
        label_id = new_label["id"]
        _label_id_cache[user_email] = label_id
        logger.info("Created Quarantine label: %s", label_id)
        return label_id


async def quarantine_message(user_email: str, message_id: str) -> None:
    """Apply the Quarantine & SPAM labels and remove from INBOX."""
    label_id = await ensure_quarantine_label(user_email)
    async with GmailClient(user_email) as client:
        await client.modify_message(
            message_id=message_id,
            add_label_ids=[label_id, "SPAM"],
            remove_label_ids=["INBOX"],
        )
    logger.info("Quarantined message %s to SPAM for %s", message_id, user_email)


async def release_from_quarantine(user_email: str, message_id: str) -> None:
    """Remove the Quarantine & SPAM labels and restore to INBOX."""
    label_id = await ensure_quarantine_label(user_email)
    async with GmailClient(user_email) as client:
        await client.modify_message(
            message_id=message_id,
            remove_label_ids=[label_id, "SPAM"],
            add_label_ids=["INBOX"],
        )
    logger.info("Released message %s from quarantine for %s", message_id, user_email)


async def invalidate_label_cache(user_email: str) -> None:
    """Force re-lookup of the label ID on next operation."""
    _label_id_cache.pop(user_email, None)
