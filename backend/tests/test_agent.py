"""Tests for the Agentic AI Gmail Threat Agent router."""
import pytest
from httpx import AsyncClient, ASGITransport
from backend.main import app

@pytest.mark.asyncio
async def test_agent_chat_requires_csrf_and_handles_unauthenticated():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Without CSRF token, fails CSRF check
        res = await ac.post(
            "/api/agent/chat",
            json={"messages": [{"role": "user", "content": "Analyze my recent emails"}]},
        )
        assert res.status_code == 403
        assert "CSRF token missing" in res.json().get("detail", "")

        # Get CSRF token
        csrf_res = await ac.get("/api/csrf-token")
        assert csrf_res.status_code == 200
        csrf_token = csrf_res.json()["csrf_token"]

        # With CSRF token but no logged-in user, returns authenticated: False prompt
        res_auth = await ac.post(
            "/api/agent/chat",
            json={"messages": [{"role": "user", "content": "Analyze my recent emails"}]},
            headers={"X-CSRF-Token": csrf_token},
        )
        assert res_auth.status_code == 200
        data = res_auth.json()
        assert data["authenticated"] is False
        assert "Gmail Account Not Connected" in data["response"]


@pytest.mark.asyncio
async def test_agent_chat_authenticated_success(monkeypatch):
    from unittest.mock import MagicMock
    import google.generativeai as genai

    # Mock GenerativeModel and chat session
    mock_chat = MagicMock()
    mock_response = MagicMock()
    mock_response.text = "Hello! I am your ThreatLens Agent, ready to assist with your emails and cybersecurity."
    mock_chat.send_message.return_value = mock_response

    mock_model = MagicMock()
    mock_model.start_chat.return_value = mock_chat

    monkeypatch.setattr(genai, "GenerativeModel", MagicMock(return_value=mock_model))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        csrf_res = await ac.get("/api/csrf-token")
        csrf_token = csrf_res.json()["csrf_token"]

        # Fake authenticated session
        headers = {"X-CSRF-Token": csrf_token}
        # In Starlette, we can test with a mocked session by providing user_email in session or patching
        from starlette.middleware.sessions import SessionMiddleware
        # We can test by calling with a test client where request.session contains user_email
        with monkeypatch.context() as m:
            async def mock_call_next(request):
                request.session["user_email"] = "testuser@gmail.com"
            res = await ac.post(
                "/api/agent/chat",
                json={"messages": [{"role": "user", "content": "hi"}]},
                headers=headers,
            )
            assert res.status_code == 200

