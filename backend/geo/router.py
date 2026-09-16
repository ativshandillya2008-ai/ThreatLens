"""ThreatLens AI Geolocation & IP Telemetry Router."""
from __future__ import annotations

import ipaddress
import logging
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..pipeline.geoip import lookup_ip_dossier, format_cardinal_coords

logger = logging.getLogger(__name__)
router = APIRouter()


def _require_auth(request: Request) -> str:
    user_email = request.session.get("user_email")
    if not user_email:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Please sign in with Google to access ThreatLens telemetry.",
        )
    return user_email


class IPLookupRequest(BaseModel):
    ip: str = Field(..., description="Target IPv4 or IPv6 address to geolocate")


class ReverseGeocodeRequest(BaseModel):
    lat: float = Field(..., ge=-90.0, le=90.0, description="Latitude")
    lon: float = Field(..., ge=-180.0, le=180.0, description="Longitude")


@router.post("/lookup")
async def lookup_ip_endpoint(req: IPLookupRequest, request: Request) -> JSONResponse:
    """Geolocate and perform 5-tier threat intelligence resolution for an IP."""
    _require_auth(request)
    target_ip = req.ip.strip()
    if not target_ip:
        raise HTTPException(status_code=400, detail="IP address cannot be empty")

    try:
        addr = ipaddress.ip_address(target_ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address format: {target_ip}")

    # Check for private or loopback ranges
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return JSONResponse({
            "ip": target_ip,
            "country": "Private / Internal Network",
            "country_code": "LAN",
            "city": "Internal RFC1918 Host",
            "lat": 0.0,
            "lon": 0.0,
            "cardinal_coords": "N/A (Private LAN)",
            "org": "Internal Network",
            "asn": "N/A",
            "isp": "Local Area Network",
            "role": "Internal RFC1918 Host",
            "confidence": 100,
            "confidence_statement": f"{target_ip} is a non-routable private local IP address",
            "threat_score": 0.0,
            "threat_tier": {
                "tier": "Safe",
                "score": 0.0,
                "color": "#4ade80",
                "bg_color": "rgba(74, 222, 128, 0.15)",
                "border_color": "#4ade80",
                "label": "INTERNAL RFC1918",
                "typical": "Local area network / non-routable private address",
            },
        })

    try:
        dossier = await lookup_ip_dossier(target_ip)
        return JSONResponse(dossier)
    except Exception as exc:
        logger.error("Failed to geolocate IP %s: %s", target_ip, exc)
        raise HTTPException(status_code=500, detail=f"Geolocation lookup failed: {exc}")


@router.post("/reverse")
async def reverse_geocode_endpoint(req: ReverseGeocodeRequest, request: Request) -> JSONResponse:
    """Reverse-geocode latitude and longitude into physical address using BigDataCloud and OSM Nominatim."""
    _require_auth(request)
    # 1. Primary: BigDataCloud Reverse Geocode Client (Free, ultra-low latency <100ms, accurate city/state/country)
    try:
        bdc_url = f"https://api.bigdatacloud.net/data/reverse-geocode-client?latitude={req.lat}&longitude={req.lon}&localityLanguage=en"
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(bdc_url)
            if resp.status_code == 200:
                data = resp.json()
                city = data.get("city") or data.get("locality") or data.get("principalSubdivision") or ""
                region = data.get("principalSubdivision") or ""
                country = data.get("countryName") or ""
                country_code = (data.get("countryCode") or "").upper()
                postcode = data.get("postcode") or ""

                parts = []
                if city:
                    parts.append(city)
                if region and region.lower() != city.lower():
                    parts.append(region)
                if country:
                    parts.append(country)

                display_name = ", ".join(parts) if parts else f"{req.lat:.4f}, {req.lon:.4f}"

                if city or country:
                    return JSONResponse({
                        "lat": req.lat,
                        "lon": req.lon,
                        "city": city or region or "Device Location",
                        "region": region,
                        "country": country or "Device Country",
                        "country_code": country_code or "LOC",
                        "postcode": postcode,
                        "display_name": display_name,
                        "cardinal_coords": format_cardinal_coords(req.lat, req.lon),
                    })
    except Exception as exc:
        logger.warning("BigDataCloud reverse geocode error: %s", exc)

    # 2. Secondary Fallback: OpenStreetMap Nominatim
    headers = {
        "User-Agent": "ThreatLens/1.0 (Cybersecurity Forensic Email Geolocation; contact@threatlens.ai)"
    }
    url = "https://nominatim.openstreetmap.org/reverse"
    params = {
        "lat": req.lat,
        "lon": req.lon,
        "format": "json",
        "zoom": 14,
        "addressdetails": 1,
    }

    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get(url, params=params, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                address = data.get("address", {})
                city = (
                    address.get("city")
                    or address.get("town")
                    or address.get("village")
                    or address.get("municipality")
                    or address.get("county")
                    or address.get("state_district")
                    or "Current Location"
                )
                region = address.get("state") or address.get("state_district") or ""
                country = address.get("country", "")
                country_code = address.get("country_code", "").upper()
                display_name = data.get("display_name", f"{city}, {country}".strip(", "))

                return JSONResponse({
                    "lat": req.lat,
                    "lon": req.lon,
                    "city": city,
                    "region": region,
                    "country": country,
                    "country_code": country_code,
                    "display_name": display_name,
                    "cardinal_coords": format_cardinal_coords(req.lat, req.lon),
                })
    except Exception as exc:
        logger.warning("Nominatim reverse geocode error: %s", exc)

    # 3. Tertiary Fallback if network completely unavailable
    return JSONResponse({
        "lat": req.lat,
        "lon": req.lon,
        "city": "GPS Location",
        "region": "",
        "country": "Device Origin",
        "country_code": "LOC",
        "display_name": f"Physical Location ({format_cardinal_coords(req.lat, req.lon)})",
        "cardinal_coords": format_cardinal_coords(req.lat, req.lon),
    })

