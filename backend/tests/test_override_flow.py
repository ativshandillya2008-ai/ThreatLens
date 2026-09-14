"""Tests for the threat override flow and CSRF protection."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ── CSRF protection tests ────────────────────────────────────────────────────

def test_csrf_validate_passes_get_requests():
    """GET requests should always pass CSRF validation regardless of token."""
    from backend.csrf import validate_csrf_token
    request = MagicMock()
    request.method = "GET"
    request.url.path = "/api/threats/"
    request.session = {}
    request.headers = {}
    # Should not raise
    validate_csrf_token(request)


def test_csrf_validate_rejects_post_without_token():
    """POST to a non-exempt path without X-CSRF-Token should raise 403."""
    from backend.csrf import validate_csrf_token
    from fastapi import HTTPException

    request = MagicMock()
    request.method = "POST"
    request.url.path = "/api/threats/abc123/override"
    request.session = {"csrf_token": "valid-session-token"}
    request.headers = {}  # No X-CSRF-Token header

    with pytest.raises(HTTPException) as exc_info:
        validate_csrf_token(request)
    assert exc_info.value.status_code == 403


def test_csrf_validate_rejects_post_with_wrong_token():
    """POST with mismatched CSRF token should raise 403."""
    from backend.csrf import validate_csrf_token
    from fastapi import HTTPException

    request = MagicMock()
    request.method = "POST"
    request.url.path = "/api/threats/abc123/override"
    request.session = {"csrf_token": "correct-token"}
    request.headers = {"X-CSRF-Token": "wrong-token"}

    with pytest.raises(HTTPException) as exc_info:
        validate_csrf_token(request)
    assert exc_info.value.status_code == 403


def test_csrf_validate_passes_post_with_correct_token():
    """POST with matching CSRF token should pass."""
    from backend.csrf import validate_csrf_token

    request = MagicMock()
    request.method = "POST"
    request.url.path = "/api/threats/abc123/override"
    request.session = {"csrf_token": "valid-token-xyz"}
    request.headers = {"X-CSRF-Token": "valid-token-xyz"}

    # Should not raise
    validate_csrf_token(request)


def test_csrf_validate_exempts_pubsub_endpoint():
    """Pub/Sub push endpoint is exempt from CSRF (uses Google JWT instead)."""
    from backend.csrf import validate_csrf_token

    request = MagicMock()
    request.method = "POST"
    request.url.path = "/api/pubsub/push"
    request.session = {}
    request.headers = {}

    # Should NOT raise — Pub/Sub is in the exempt list
    validate_csrf_token(request)


def test_csrf_validate_exempts_auth_endpoints():
    """Auth endpoints are exempt from CSRF checks."""
    from backend.csrf import validate_csrf_token

    request = MagicMock()
    request.method = "POST"
    request.url.path = "/auth/logout"
    request.session = {}
    request.headers = {}

    # Should not raise
    validate_csrf_token(request)


def test_csrf_get_or_create_generates_token():
    """get_or_create_csrf_token should create a new token if none exists."""
    from backend.csrf import get_or_create_csrf_token

    session = {}
    request = MagicMock()
    request.session = session

    token = get_or_create_csrf_token(request)
    assert token is not None
    assert len(token) >= 32
    assert session.get("csrf_token") == token


def test_csrf_get_or_create_reuses_existing_token():
    """get_or_create_csrf_token should return the same token on repeated calls."""
    from backend.csrf import get_or_create_csrf_token

    existing = "existing-token-abc123"
    request = MagicMock()
    request.session = {"csrf_token": existing}

    token = get_or_create_csrf_token(request)
    assert token == existing


# ── Override flow tests ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_override_requires_authentication():
    """Override endpoint must return 401 for unauthenticated users."""
    from backend.threats.router import override_threat, OverrideRequest
    from fastapi import HTTPException

    request = MagicMock()
    request.session = {}  # No user_email

    with pytest.raises(HTTPException) as exc_info:
        await override_threat(request, "threat-id", OverrideRequest(action="release"))
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_override_rejects_invalid_action():
    """Override must reject actions other than 'release' or 'confirm'."""
    from backend.threats.router import override_threat, OverrideRequest
    from fastapi import HTTPException

    request = MagicMock()
    request.session = {"user_email": "user@example.com"}

    # Pydantic validates the action field type; test the router-level guard
    with pytest.raises(HTTPException) as exc_info:
        await override_threat(
            request, "threat-id", OverrideRequest(action="delete")
        )
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_override_returns_404_for_wrong_user():
    """Override must not allow a user to act on another user's threat record."""
    from backend.threats.router import override_threat, OverrideRequest
    from fastapi import HTTPException

    request = MagicMock()
    request.session = {"user_email": "attacker@example.com"}

    # scalar_one_or_none() returns None synchronously — use MagicMock not AsyncMock
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.add = MagicMock()  # add() is synchronous
    mock_session.commit = AsyncMock()

    with patch("backend.threats.router.get_session_factory") as mock_factory:
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
        mock_ctx.__aexit__ = AsyncMock(return_value=None)
        mock_factory.return_value.return_value = mock_ctx

        with pytest.raises(HTTPException) as exc_info:
            await override_threat(
                request, "victim-threat-id", OverrideRequest(action="release")
            )
    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_override_release_calls_quarantine_release():
    """Successful 'release' override should call release_from_quarantine."""
    from backend.threats.router import override_threat, OverrideRequest
    from backend.threats.models import ThreatScore

    request = MagicMock()
    request.session = {"user_email": "user@example.com"}

    # Create a mock ThreatScore record
    mock_record = MagicMock(spec=ThreatScore)
    mock_record.quarantined = True
    mock_record.message_id = "msg-abc"

    # Execute must be AsyncMock returning a MagicMock whose .scalar_one_or_none() returns sync
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_record
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.add = MagicMock()
    mock_session.commit = AsyncMock()

    mock_override = MagicMock()
    mock_override.id = "override-uuid-123"

    with patch("backend.threats.router.get_session_factory") as mock_factory, \
         patch("backend.threats.router.AuditOverride", return_value=mock_override), \
         patch("backend.threats.router.release_from_quarantine", new_callable=AsyncMock) as mock_release:

        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
        mock_ctx.__aexit__ = AsyncMock(return_value=None)
        mock_factory.return_value.return_value = mock_ctx

        response = await override_threat(
            request, "threat-id", OverrideRequest(action="release", reason="Verified safe")
        )

    mock_release.assert_called_once_with("user@example.com", "msg-abc")


@pytest.mark.asyncio
async def test_override_confirm_does_not_call_release():
    """'confirm' action should NOT release from quarantine."""
    from backend.threats.router import override_threat, OverrideRequest
    from backend.threats.models import ThreatScore

    request = MagicMock()
    request.session = {"user_email": "user@example.com"}

    mock_record = MagicMock(spec=ThreatScore)
    mock_record.quarantined = True
    mock_record.message_id = "msg-abc"

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_record
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.add = MagicMock()
    mock_session.commit = AsyncMock()

    mock_override = MagicMock()
    mock_override.id = "override-uuid-456"

    with patch("backend.threats.router.get_session_factory") as mock_factory, \
         patch("backend.threats.router.AuditOverride", return_value=mock_override), \
         patch("backend.threats.router.release_from_quarantine", new_callable=AsyncMock) as mock_release:

        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
        mock_ctx.__aexit__ = AsyncMock(return_value=None)
        mock_factory.return_value.return_value = mock_ctx

        await override_threat(
            request, "threat-id", OverrideRequest(action="confirm")
        )

    mock_release.assert_not_called()
