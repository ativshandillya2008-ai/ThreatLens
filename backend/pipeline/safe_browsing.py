"""Google Safe Browsing v4 URL reputation check."""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from email.message import Message
from typing import Any

import httpx
from bs4 import BeautifulSoup
from cachetools import TTLCache

from ..config import get_settings

logger = logging.getLogger(__name__)

SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)

# LRU cache: up to 1000 URLs, 1-hour TTL
_url_cache: TTLCache = TTLCache(maxsize=1000, ttl=3600)

URL_REGEX = re.compile(r'https?://[^\s<>"\']+')

CLIENT_INFO = {
    "clientId": "threatlens",
    "clientVersion": "1.0.0",
}

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


@dataclass
class SafeBrowsingResult:
    urls_checked: list[str] = field(default_factory=list)
    unsafe_urls: dict[str, str] = field(default_factory=dict)  # url -> threat_type
    score: float = 0.0
    available: bool = True
    evidence: dict = field(default_factory=dict)


def _extract_urls(msg: Message) -> list[str]:
    """Extract all URLs from the email body (both plain text and HTML)."""
    urls: list[str] = []

    def _from_text(text: str) -> list[str]:
        found = URL_REGEX.findall(text)
        return [u.rstrip(".,:;)>]") for u in found]

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            try:
                charset = part.get_content_charset() or "utf-8"
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                text = payload.decode(charset, errors="replace")
                if content_type == "text/html":
                    soup = BeautifulSoup(text, "html.parser")
                    for tag in soup.find_all(["a", "img", "link"]):
                        href = tag.get("href") or tag.get("src") or ""
                        if href.startswith("http"):
                            urls.append(href.rstrip(".,:;)>]"))
                    urls.extend(_from_text(text))
                else:
                    urls.extend(_from_text(text))
            except Exception:
                pass
    else:
        try:
            charset = msg.get_content_charset() or "utf-8"
            payload = msg.get_payload(decode=True)
            if payload:
                text = payload.decode(charset, errors="replace")
                if msg.get_content_type() == "text/html":
                    soup = BeautifulSoup(text, "html.parser")
                    for tag in soup.find_all(["a", "img"]):
                        href = tag.get("href") or tag.get("src") or ""
                        if href.startswith("http"):
                            urls.append(href.rstrip(".,:;)>]"))
                urls.extend(_from_text(text))
        except Exception:
            pass

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            unique.append(u)
    return unique[:50]  # Cap at 50 URLs per email


async def _resolve_redirect(url: str) -> str:
    """Follow redirects to resolve shortened/obfuscated URLs."""
    try:
        async with httpx.AsyncClient(
            follow_redirects=True, timeout=3.0, verify=False
        ) as client:
            response = await client.head(url, timeout=3.0)
            return str(response.url)
    except Exception:
        return url


async def _check_safe_browsing(urls: list[str], api_key: str) -> dict[str, str]:
    """Check URLs against Google Safe Browsing v4 API."""
    if not urls:
        return {}

    uncached = [u for u in urls if u not in _url_cache]
    cached_results: dict[str, str] = {}
    for u in urls:
        if u in _url_cache and _url_cache[u]:
            cached_results[u] = _url_cache[u]

    if not uncached:
        return cached_results

    payload = {
        "client": CLIENT_INFO,
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in uncached],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                SAFE_BROWSING_URL,
                params={"key": api_key},
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        logger.error("Safe Browsing API error: %s", exc)
        return cached_results

    matches: dict[str, str] = {}
    for match in data.get("matches", []):
        url = match.get("threat", {}).get("url", "")
        threat_type = match.get("threatType", "UNKNOWN")
        if url:
            matches[url] = threat_type

    # Update cache
    for u in uncached:
        _url_cache[u] = matches.get(u, "")

    return {**cached_results, **matches}


async def score_safe_browsing(msg: Message) -> SafeBrowsingResult:
    """Check all URLs in the email against Google Safe Browsing.

    Fail-open: returns score=0.0 if API key not configured or API fails.
    """
    settings = get_settings()

    if not settings.SAFE_BROWSING_API_KEY:
        logger.warning("SAFE_BROWSING_API_KEY not set — skipping URL check")
        return SafeBrowsingResult(
            score=0.0,
            available=False,
            evidence={"reason": "SAFE_BROWSING_API_KEY not configured"},
        )

    urls = _extract_urls(msg)
    if not urls:
        return SafeBrowsingResult(
            urls_checked=[],
            score=0.0,
            evidence={"reason": "No URLs found in email"},
        )

    # Resolve redirects for first 10 URLs concurrently
    head_urls = urls[:10]
    tail_urls = urls[10:]
    resolved_head = await asyncio.gather(
        *[_resolve_redirect(u) for u in head_urls],
        return_exceptions=True,
    )
    resolved_urls = [
        r if isinstance(r, str) else u
        for r, u in zip(resolved_head, head_urls)
    ]
    resolved_urls.extend(tail_urls)

    unsafe = await _check_safe_browsing(
        list(set(resolved_urls)), settings.SAFE_BROWSING_API_KEY
    )

    score = 1.0 if unsafe else 0.0

    logger.info(
        "Safe Browsing: %d URLs checked, %d unsafe -> score=%.1f",
        len(resolved_urls), len(unsafe), score,
    )

    return SafeBrowsingResult(
        urls_checked=resolved_urls,
        unsafe_urls=unsafe,
        score=score,
        available=True,
        evidence={
            "total_urls": len(urls),
            "urls_checked": len(resolved_urls),
            "unsafe_count": len(unsafe),
        },
    )
