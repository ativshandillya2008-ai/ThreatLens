"""SPF / DKIM / DMARC validation stage.

Primary approach: Parse the Authentication-Results: header per RFC 7601.
Fallback: Run checkdmarc for independent DMARC DNS lookup.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from email.message import Message
from typing import Optional

logger = logging.getLogger(__name__)

# Regex to extract per-method results from Authentication-Results header
AUTH_RESULT_PATTERN = re.compile(
    r'(spf|dkim|dmarc)=(pass|fail|softfail|neutral|none|temperror|permerror)',
    re.IGNORECASE,
)


@dataclass
class AuthResult:
    spf: str = "none"       # pass|fail|softfail|neutral|none|error
    dkim: str = "none"
    dmarc: str = "none"
    score: float = 0.0
    evidence: dict = field(default_factory=dict)


def _parse_authentication_results(msg: Message) -> dict[str, str]:
    """Extract SPF/DKIM/DMARC results from Authentication-Results headers."""
    results: dict[str, str] = {}

    for header_value in msg.get_all("Authentication-Results", []):
        for match in AUTH_RESULT_PATTERN.finditer(header_value):
            method = match.group(1).lower()
            result = match.group(2).lower()
            # First occurrence wins (most authoritative MTA)
            if method not in results:
                results[method] = result

    return results


def _compute_score(spf: str, dkim: str, dmarc: str) -> float:
    """Compute a threat contribution score from auth results.

    Scoring logic:
    - All pass           → 0.0 (no threat contribution)
    - Any softfail       → 0.3
    - DMARC fail alone   → 0.5
    - SPF fail + no DKIM → 0.7
    - All fail           → 1.0
    """
    fail_count = sum(1 for r in [spf, dkim, dmarc] if r in ("fail", "permerror"))
    softfail = any(r == "softfail" for r in [spf, dkim, dmarc])
    all_none = all(r == "none" for r in [spf, dkim, dmarc])

    if all_none:
        # No authentication headers at all — suspicious but not definitive
        return 0.4

    if fail_count == 0 and not softfail:
        return 0.0

    if softfail and fail_count == 0:
        return 0.3

    if dmarc in ("fail", "permerror") and fail_count == 1:
        return 0.5

    if spf in ("fail", "permerror") and dkim == "none":
        return 0.7

    if fail_count >= 2:
        return 0.85

    if fail_count == 3:
        return 1.0

    return min(0.3 * fail_count + (0.15 if softfail else 0.0), 1.0)


async def score_spf_dkim_dmarc(msg: Message) -> AuthResult:
    """Run SPF/DKIM/DMARC analysis and return a scored AuthResult."""
    parsed = _parse_authentication_results(msg)
    spf = parsed.get("spf", "none")
    dkim = parsed.get("dkim", "none")
    dmarc = parsed.get("dmarc", "none")

    evidence = {
        "source": "Authentication-Results header",
        "spf_raw": spf,
        "dkim_raw": dkim,
        "dmarc_raw": dmarc,
    }

    # Fallback: if DMARC result is missing, try checkdmarc
    if dmarc == "none":
        sender = msg.get("From", "")
        domain = _extract_domain(sender)
        if domain:
            try:
                dmarc_data = await _run_checkdmarc(domain)
                if dmarc_data:
                    evidence["checkdmarc"] = dmarc_data
                    if not dmarc_data.get("valid"):
                        dmarc = "fail"  # Malformed DMARC record
            except Exception as exc:
                logger.warning("checkdmarc failed for %s: %s", domain, exc)

    score = _compute_score(spf, dkim, dmarc)
    logger.info("Auth scores: spf=%s dkim=%s dmarc=%s -> score=%.2f", spf, dkim, dmarc, score)

    return AuthResult(
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        score=score,
        evidence=evidence,
    )


def _extract_domain(from_header: str) -> Optional[str]:
    """Extract the domain from a From: header."""
    match = re.search(r'@([\w.-]+)', from_header)
    if match:
        return match.group(1).lower()
    return None


async def _run_checkdmarc(domain: str) -> Optional[dict]:
    """Run checkdmarc for independent DMARC validation."""
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        import checkdmarc
        result = await loop.run_in_executor(None, checkdmarc.check_domains, [domain])
        if result:
            return result[0]
    except Exception as exc:
        logger.debug("checkdmarc error for %s: %s", domain, exc)
    return None
