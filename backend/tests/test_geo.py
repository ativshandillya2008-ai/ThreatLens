"""Tests for ThreatLens Geolocation, Reverse-Hop Traversal, and 5-Tier Scoring."""
from __future__ import annotations

import email
import pytest
from httpx import AsyncClient, ASGITransport

from backend.main import app
from backend.pipeline.geoip import (
    _extract_received_ips,
    format_cardinal_coords,
    get_ip_threat_tier,
    lookup_ip_dossier,
)


def test_format_cardinal_coords():
    """Format decimal lat/lon into cardinal representation."""
    res1 = format_cardinal_coords(55.7558, 37.6173)
    assert res1 == "55.7558° N, 37.6173° E"

    res2 = format_cardinal_coords(-33.8688, 151.2093)
    assert res2 == "33.8688° S, 151.2093° E"

    res3 = format_cardinal_coords(None, None)
    assert res3 == "N/A"


def test_five_tier_threat_scoring():
    """Verify 5-tier threat classification colors and thresholds."""
    critical = get_ip_threat_tier(90)
    assert critical["tier"] == "Critical"
    assert critical["color"] == "#990000"

    high = get_ip_threat_tier(72)
    assert high["tier"] == "High"
    assert high["color"] == "#f87171"

    medium = get_ip_threat_tier(50)
    assert medium["tier"] == "Medium"
    assert medium["color"] == "#facc15"

    low = get_ip_threat_tier(25)
    assert low["tier"] == "Low"
    assert low["color"] == "#166534"

    safe = get_ip_threat_tier(5)
    assert safe["tier"] == "Safe"
    assert safe["color"] == "#4ade80"


def test_reverse_hop_traversal_and_origin_headers():
    """Explicit origin header takes priority and received headers are traversed bottom-to-top."""
    raw = (
        "X-Originating-IP: [194.26.29.112]\n"
        "Received: from client ([10.0.0.5]) by mail.relay.com\n"
        "Received: from relay ([185.220.101.5]) by mx.google.com\n"
        "Received: from google ([209.85.220.41]) by client.box\n\n"
        "Test email"
    )
    msg = email.message_from_string(raw)
    ips = _extract_received_ips(msg)

    # 10.0.0.5 must be filtered out
    assert "10.0.0.5" not in ips
    # Explicit origin IP is first
    assert ips[0] == "194.26.29.112"
    assert "185.220.101.5" in ips
    assert "209.85.220.41" in ips


@pytest.mark.asyncio
async def test_curated_threat_infrastructure_resolution():
    """Verify curated adversary C2 / Tor exit infrastructure resolves with known forensics."""
    res = await lookup_ip_dossier("185.220.101.5")
    assert res["city"] == "Moscow"
    assert res["country"] == "Russia"
    assert res["threat_tier"]["tier"] == "Critical"
    assert res["threat_tier"]["color"] == "#990000"
    assert "95% confidence" in res["confidence_statement"]


@pytest.mark.asyncio
async def test_geo_lookup_endpoint():
    """Test POST /api/geo/lookup endpoint."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Public IP lookup
        resp = await client.post("/api/geo/lookup", json={"ip": "8.8.8.8"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ip"] == "8.8.8.8"
        assert data["city"] == "Mountain View"
        assert data["threat_tier"]["tier"] == "Safe"

        # Private LAN IP lookup
        resp_lan = await client.post("/api/geo/lookup", json={"ip": "192.168.1.1"})
        assert resp_lan.status_code == 200
        data_lan = resp_lan.json()
        assert data_lan["country_code"] == "LAN"
        assert data_lan["threat_score"] == 0.0

        # Invalid IP format
        resp_bad = await client.post("/api/geo/lookup", json={"ip": "not-an-ip"})
        assert resp_bad.status_code == 400


@pytest.mark.asyncio
async def test_geo_reverse_endpoint():
    """Test POST /api/geo/reverse endpoint for GPS coordinates."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/geo/reverse", json={"lat": 13.3208, "lon": 77.0923})
        assert resp.status_code == 200
        data = resp.json()
        assert "lat" in data
        assert "lon" in data
        assert "cardinal_coords" in data
        # Ensure actual place name is returned rather than raw fallback
        assert "city" in data
        assert "India" in data.get("country", "") or "India" in data.get("display_name", "")
        assert "Tumkur" in data.get("display_name", "") or "Karnataka" in data.get("display_name", "")

