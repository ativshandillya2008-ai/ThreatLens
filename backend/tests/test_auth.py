"""Auth flow tests."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.mark.asyncio
async def test_generate_pkce_pair():
    """PKCE code_verifier and code_challenge should be distinct and correct length."""
    from backend.auth.oauth import generate_pkce_pair
    import base64
    import hashlib

    verifier, challenge = generate_pkce_pair()
    assert len(verifier) > 40
    assert len(challenge) > 40
    assert verifier != challenge

    # Verify the S256 relationship
    digest = hashlib.sha256(verifier.encode()).digest()
    expected_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert challenge == expected_challenge


@pytest.mark.asyncio
async def test_build_authorization_url_contains_pkce():
    """Authorization URL should contain code_challenge and code_challenge_method."""
    from backend.auth.oauth import build_authorization_url

    with patch("backend.auth.oauth.get_settings") as mock_settings:
        mock_settings.return_value.GOOGLE_CLIENT_ID = "test-client-id"
        mock_settings.return_value.OAUTH_REDIRECT_URI = "http://localhost:8088/auth/callback"
        mock_settings.return_value.OAUTH_SCOPES = "openid email profile"

        url = build_authorization_url(state="test-state", code_challenge="test-challenge")

    assert "code_challenge=test-challenge" in url
    assert "code_challenge_method=S256" in url
    assert "state=test-state" in url
    assert "access_type=offline" in url
    assert "prompt=select_account%20consent" in url or "prompt=consent" in url


@pytest.mark.asyncio
async def test_encrypt_decrypt_token_roundtrip():
    """Token encryption should be reversible and produce different ciphertext."""
    from backend.crypto import encrypt_token, decrypt_token

    with patch("backend.crypto.get_settings") as mock_settings:
        from cryptography.fernet import Fernet
        key = Fernet.generate_key().decode()
        mock_settings.return_value.FERNET_KEY = key

        plaintext = "ya29.a0ARrdaM-test-refresh-token-value"
        ciphertext = encrypt_token(plaintext)

        assert ciphertext != plaintext
        assert len(ciphertext) > len(plaintext)
        assert decrypt_token(ciphertext) == plaintext


@pytest.mark.asyncio
async def test_decrypt_tampered_token_raises():
    """Tampered ciphertext should raise ValueError."""
    from backend.crypto import decrypt_token

    with patch("backend.crypto.get_settings") as mock_settings:
        from cryptography.fernet import Fernet
        key = Fernet.generate_key().decode()
        mock_settings.return_value.FERNET_KEY = key

        with pytest.raises(ValueError, match="decryption failed"):
            decrypt_token("definitely-not-valid-ciphertext")


@pytest.mark.asyncio
async def test_token_exchange_sends_code_verifier():
    """Token exchange must send code_verifier (PKCE) to Google."""
    from backend.auth.oauth import exchange_code_for_tokens

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {
        "access_token": "access-123",
        "refresh_token": "refresh-456",
        "expires_in": 3600,
    }

    captured_data = {}

    async def mock_post(url, data=None, **kwargs):
        captured_data.update(data or {})
        return mock_response

    with patch("backend.auth.oauth.get_settings") as mock_settings, \
         patch("httpx.AsyncClient") as mock_client:
        mock_settings.return_value.GOOGLE_CLIENT_ID = "client-id"
        mock_settings.return_value.GOOGLE_CLIENT_SECRET = "client-secret"
        mock_settings.return_value.OAUTH_REDIRECT_URI = "http://localhost/callback"

        mock_client.return_value.__aenter__.return_value.post = mock_post

        result = await exchange_code_for_tokens("auth-code", "my-verifier")

    assert captured_data.get("code_verifier") == "my-verifier"
    assert captured_data.get("grant_type") == "authorization_code"
    assert result["access_token"] == "access-123"


@pytest.mark.asyncio
async def test_login_endpoint_redirects_to_google():
    """GET /auth/login must set session PKCE and redirect to Google OAuth URL."""
    from backend.auth.router import login

    request = MagicMock()
    request.session = {}
    request.headers = {}
    request.url = MagicMock(scheme="https", netloc="test.trycloudflare.com")

    response = await login(request)
    assert response.status_code == 307
    assert "accounts.google.com" in response.headers["location"]
    assert "oauth_state" in request.session
    assert "oauth_code_verifier" in request.session
