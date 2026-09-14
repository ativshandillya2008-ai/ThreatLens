"""Pipeline unit tests using real email fixtures.

Tests each stage in isolation and validates end-to-end scoring behavior
for the canonical phishing and benign test cases.
"""
from __future__ import annotations

import email
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


# ── SPF/DKIM/DMARC stage ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_spf_fail_scores_high(phishing_msg):
    """Phishing email with SPF/DKIM/DMARC fail should score > 0.5"""
    from backend.pipeline.spf_dkim_dmarc import score_spf_dkim_dmarc
    result = await score_spf_dkim_dmarc(phishing_msg)
    assert result.spf == "fail"
    assert result.dkim == "none"
    assert result.dmarc == "fail"
    assert result.score >= 0.5


@pytest.mark.asyncio
async def test_spf_pass_scores_zero(benign_msg):
    """Benign email with all-pass authentication should score 0.0"""
    from backend.pipeline.spf_dkim_dmarc import score_spf_dkim_dmarc
    result = await score_spf_dkim_dmarc(benign_msg)
    assert result.spf == "pass"
    assert result.dkim == "pass"
    assert result.dmarc == "pass"
    assert result.score == 0.0


@pytest.mark.asyncio
async def test_auth_score_computation():
    """Unit test for score computation logic."""
    from backend.pipeline.spf_dkim_dmarc import _compute_score
    assert _compute_score("pass", "pass", "pass") == 0.0
    # 3 failures hit fail_count >= 2 branch first → 0.85
    assert _compute_score("fail", "fail", "fail") == 0.85
    assert _compute_score("softfail", "pass", "pass") == 0.3
    assert _compute_score("none", "none", "none") == 0.4


# ── GeoIP stage ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_geoip_extracts_external_ip(phishing_msg):
    """Should extract the external IP from phishing email's Received header."""
    from backend.pipeline.geoip import _extract_received_ips
    ips = _extract_received_ips(phishing_msg)
    assert "185.220.101.47" in ips


@pytest.mark.asyncio
async def test_geoip_filters_private_ips():
    """Private/loopback IPs should be filtered out."""
    from backend.pipeline.geoip import _extract_received_ips
    raw = (
        "Received: from localhost ([127.0.0.1]) by mx.google.com\n"
        "Received: from internal ([10.0.0.1]) by mx.google.com\n"
        "Received: from evil.ru ([185.220.101.47]) by mx.google.com"
    )
    msg = email.message_from_string(raw)
    ips = _extract_received_ips(msg)
    assert "127.0.0.1" not in ips
    assert "10.0.0.1" not in ips
    assert "185.220.101.47" in ips


@pytest.mark.asyncio
async def test_geoip_no_external_ips_scores_zero():
    """Email with only private IPs should score 0."""
    from backend.pipeline.geoip import score_geoip
    raw = "Received: from localhost ([127.0.0.1]) by mx.google.com\n\nBody"
    msg = email.message_from_string(raw)
    result = await score_geoip(msg)
    assert result.score == 0.0


# ── LLM stage ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_llm_skips_when_no_api_key(phishing_msg, monkeypatch):
    """LLM stage should fail-open when GEMINI_API_KEY is not set."""
    from backend.pipeline.llm_analyzer import score_llm
    from backend.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "")
    # Bust the lru_cache so monkeypatch takes effect
    get_settings.cache_clear()

    # Re-import with patched settings
    with patch("backend.pipeline.llm_analyzer.get_settings") as mock_settings:
        mock_settings.return_value.GEMINI_API_KEY = ""
        result = await score_llm(phishing_msg)
    assert result.score == 0.0
    assert result.available is False


@pytest.mark.asyncio
async def test_llm_parse_valid_response():
    """LLM response parser should correctly extract score and reasoning."""
    from backend.pipeline.llm_analyzer import _parse_llm_response
    response = '{"threat_score": 0.92, "threat_type": "phishing", "reasoning": ["Urgency tactics", "Suspicious link"], "suspicious_phrases": ["verify immediately"]}'
    result = _parse_llm_response(response)
    assert result["threat_score"] == 0.92
    assert result["threat_type"] == "phishing"
    assert len(result["reasoning"]) == 2


@pytest.mark.asyncio
async def test_llm_handles_json_fenced_response():
    """Parser should strip markdown fences."""
    from backend.pipeline.llm_analyzer import _parse_llm_response
    response = '```json\n{"threat_score": 0.1, "threat_type": "legitimate", "reasoning": [], "suspicious_phrases": []}\n```'
    result = _parse_llm_response(response)
    assert result["threat_score"] == 0.1


# ── Safe Browsing stage ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_safe_browsing_extracts_urls(phishing_msg):
    """Should extract the malicious URL from the phishing email body."""
    from backend.pipeline.safe_browsing import _extract_urls
    urls = _extract_urls(phishing_msg)
    assert any("paypal-verify-login.ru" in u for u in urls)


@pytest.mark.asyncio
async def test_safe_browsing_no_key_scores_zero(phishing_msg):
    """Should fail-open when SAFE_BROWSING_API_KEY is not set."""
    from backend.pipeline.safe_browsing import score_safe_browsing
    with patch("backend.pipeline.safe_browsing.get_settings") as mock_settings:
        mock_settings.return_value.SAFE_BROWSING_API_KEY = ""
        result = await score_safe_browsing(phishing_msg)
    assert result.score == 0.0
    assert result.available is False


@pytest.mark.asyncio
async def test_safe_browsing_hit_scores_one():
    """A Safe Browsing API match should produce score=1.0."""
    from backend.pipeline.safe_browsing import _check_safe_browsing
    with patch("httpx.AsyncClient") as mock_client:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "matches": [{
                "threat": {"url": "http://evil.ru/malware"},
                "threatType": "MALWARE"
            }]
        }
        mock_response.raise_for_status = MagicMock()
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_response)

        result = await _check_safe_browsing(["http://evil.ru/malware"], "fake-key")
    assert "http://evil.ru/malware" in result
    assert result["http://evil.ru/malware"] == "MALWARE"


# ── Integration: phishing email scores HIGH ──────────────────────────────────

@pytest.mark.asyncio
async def test_phishing_email_scores_high(phishing_msg):
    """End-to-end: phishing fixture should score >= 0.5 from auth alone."""
    from backend.pipeline.spf_dkim_dmarc import score_spf_dkim_dmarc
    from backend.pipeline.geoip import _extract_received_ips

    auth = await score_spf_dkim_dmarc(phishing_msg)
    ips = _extract_received_ips(phishing_msg)

    assert auth.score >= 0.5, "Phishing email auth score should be high"
    assert len(ips) > 0, "Should extract at least one external IP"


@pytest.mark.asyncio
async def test_benign_email_scores_low(benign_msg):
    """End-to-end: benign fixture should score 0 from auth stage."""
    from backend.pipeline.spf_dkim_dmarc import score_spf_dkim_dmarc

    auth = await score_spf_dkim_dmarc(benign_msg)
    assert auth.score == 0.0, "Benign email auth score should be zero"


# ── Quarantine logic ─────────────────────────────────────────────────────────

def test_severity_thresholds():
    """Test severity threshold computation."""
    from backend.pipeline.runner import _compute_severity
    from unittest.mock import patch

    with patch("backend.pipeline.runner.get_settings") as mock_s:
        mock_s.return_value.THRESHOLD_HIGH = 0.70
        mock_s.return_value.THRESHOLD_MEDIUM = 0.40

        assert _compute_severity(0.85) == "HIGH"
        assert _compute_severity(0.55) == "MEDIUM"
        assert _compute_severity(0.20) == "LOW"
        assert _compute_severity(0.70) == "HIGH"
        assert _compute_severity(0.40) == "MEDIUM"
        assert _compute_severity(0.39) == "LOW"
