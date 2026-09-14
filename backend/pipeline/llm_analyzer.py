"""LLM-based email content analysis using Gemini 1.5 Flash.

Fail-open: if the LLM is unavailable or returns malformed output,
returns a 0.0 score with a warning logged (never blocks processing).
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from email.message import Message
from typing import Any

from ..config import get_settings

logger = logging.getLogger(__name__)

MAX_BODY_CHARS = 4000

LLM_PROMPT_TEMPLATE = """You are an email security analyst with expertise in phishing and social engineering detection.
Analyze the following email for threat indicators.

Return ONLY a valid JSON object with exactly these fields:
{{
  "threat_score": <float between 0.0 and 1.0>,
  "threat_type": "<one of: phishing, social_engineering, malware_lure, suspicious, legitimate>",
  "reasoning": ["<bullet 1>", "<bullet 2>", ...],
  "suspicious_phrases": ["<exact phrase from email>"]
}}

Guidelines:
- threat_score 0.0 = definitely legitimate, 1.0 = definite phishing/attack
- reasoning: max 5 bullet points explaining your assessment
- suspicious_phrases: exact quotes from the email body that are red flags (empty list if none)
- Do NOT include any text outside the JSON object

Email to analyze:
---
From: {from_header}
Subject: {subject}
Date: {date}

{body}
---"""


@dataclass
class LLMResult:
    score: float = 0.0
    threat_type: str = "unknown"
    reasoning: list[str] = field(default_factory=list)
    suspicious_phrases: list[str] = field(default_factory=list)
    available: bool = True
    evidence: dict = field(default_factory=dict)


def _extract_text_body(msg: Message) -> str:
    """Extract plain text from the email, stripping HTML."""
    text_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                try:
                    charset = part.get_content_charset() or "utf-8"
                    text_parts.append(part.get_payload(decode=True).decode(charset, errors="replace"))
                except Exception:
                    pass
            elif content_type == "text/html" and not text_parts:
                try:
                    from bs4 import BeautifulSoup
                    charset = part.get_content_charset() or "utf-8"
                    html = part.get_payload(decode=True).decode(charset, errors="replace")
                    soup = BeautifulSoup(html, "html.parser")
                    text_parts.append(soup.get_text(separator=" ", strip=True))
                except Exception:
                    pass
    else:
        content_type = msg.get_content_type()
        try:
            charset = msg.get_content_charset() or "utf-8"
            payload = msg.get_payload(decode=True)
            if payload:
                text = payload.decode(charset, errors="replace")
                if content_type == "text/html":
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(text, "html.parser")
                    text = soup.get_text(separator=" ", strip=True)
                text_parts.append(text)
        except Exception:
            pass

    combined = " ".join(text_parts)
    return combined[:MAX_BODY_CHARS]


def _parse_llm_response(response_text: str) -> dict[str, Any]:
    """Parse and validate the LLM's JSON response."""
    text = response_text.strip()
    text = re.sub(r'^```(?:json)?\s*', '', text)
    text = re.sub(r'\s*```$', '', text)

    data = json.loads(text)

    score = float(data.get("threat_score", 0.0))
    score = max(0.0, min(1.0, score))

    threat_type = data.get("threat_type", "unknown")
    valid_types = {"phishing", "social_engineering", "malware_lure", "suspicious", "legitimate", "unknown"}
    if threat_type not in valid_types:
        threat_type = "suspicious"

    reasoning = data.get("reasoning", [])
    if not isinstance(reasoning, list):
        reasoning = [str(reasoning)]
    reasoning = reasoning[:5]

    phrases = data.get("suspicious_phrases", [])
    if not isinstance(phrases, list):
        phrases = []

    return {
        "threat_score": score,
        "threat_type": threat_type,
        "reasoning": reasoning,
        "suspicious_phrases": phrases,
    }


async def score_llm(msg: Message) -> LLMResult:
    """Run LLM-based content analysis on the email.

    Fail-open: returns score=0.0 if LLM is unavailable.
    """
    settings = get_settings()

    if not settings.GEMINI_API_KEY:
        logger.warning("GEMINI_API_KEY not set — skipping LLM analysis")
        return LLMResult(
            score=0.0,
            threat_type="unknown",
            available=False,
            evidence={"reason": "GEMINI_API_KEY not configured"},
        )

    from_header = msg.get("From", "(unknown)")
    subject = msg.get("Subject", "(no subject)")
    date = msg.get("Date", "(unknown)")
    body = _extract_text_body(msg)

    if not body.strip():
        logger.warning("Empty email body — skipping LLM analysis")
        return LLMResult(
            score=0.1,
            threat_type="suspicious",
            reasoning=["Email has no readable body content"],
            evidence={"reason": "Empty body"},
        )

    prompt = LLM_PROMPT_TEMPLATE.format(
        from_header=from_header,
        subject=subject,
        date=date,
        body=body,
    )

    try:
        import google.generativeai as genai
        import asyncio

        genai.configure(api_key=settings.GEMINI_API_KEY)
        configured_model = getattr(settings, "GEMINI_MODEL", "gemini-flash-latest") or "gemini-flash-latest"
        candidate_models = [configured_model]
        for fallback in ["gemini-flash-latest", "gemini-3.5-flash", "gemini-3.8-flash", "gemini-3.7-flash"]:
            if fallback not in candidate_models:
                candidate_models.append(fallback)

        response = None
        last_error = None
        loop = asyncio.get_event_loop()

        for m_name in candidate_models:
            try:
                model = genai.GenerativeModel(
                    m_name,
                    generation_config=genai.GenerationConfig(
                        temperature=0.1,
                        max_output_tokens=2048,
                        response_mime_type="application/json",
                    ),
                )
                response = await loop.run_in_executor(
                    None,
                    lambda: model.generate_content(prompt),
                )
                if response and response.text:
                    break
            except Exception as exc:
                last_error = exc
                logger.warning("Gemini model %s failed: %s, trying fallback", m_name, exc)

        if not response or not response.text:
            raise last_error or RuntimeError("All Gemini candidate models failed")

        raw_text = response.text
        parsed = _parse_llm_response(raw_text)

        logger.info(
            "LLM analysis: type=%s score=%.2f",
            parsed["threat_type"], parsed["threat_score"],
        )

        return LLMResult(
            score=parsed["threat_score"],
            threat_type=parsed["threat_type"],
            reasoning=parsed["reasoning"],
            suspicious_phrases=parsed["suspicious_phrases"],
            available=True,
            evidence={"raw_prompt_chars": len(prompt), "body_chars": len(body)},
        )

    except json.JSONDecodeError as exc:
        logger.error("LLM returned invalid JSON: %s", exc)
        return LLMResult(
            score=0.0,
            threat_type="unknown",
            available=True,
            evidence={"error": "JSON parse failure", "detail": str(exc)},
        )
    except Exception as exc:
        logger.error("LLM analysis failed: %s", exc)
        return LLMResult(
            score=0.0,
            threat_type="unknown",
            available=False,
            evidence={"error": str(exc)},
        )
