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
from typing import Any, Optional

from ..config import get_settings
from .language_detector import detect_indian_language_hint

logger = logging.getLogger(__name__)

MAX_BODY_CHARS = 4000

LLM_PROMPT_TEMPLATE = """You are ThreatLens Multilingual Email Security Analyst, an expert in detecting phishing, cybercrime, and social engineering attacks across global languages and Indian native languages (including Hindi, Bengali, Tamil, Telugu, Marathi, Gujarati, Kannada, Malayalam, Punjabi, Odia, Urdu, Assamese, and Hinglish).

Analyze the following email for threat indicators. Pay special attention to Indian financial, institutional, and regional cyber scams:
- Bank account / NetBanking KYC deactivation or PAN-Aadhaar linking scams (SBI, HDFC, ICICI, Axis, PNB, etc.)
- Electricity bill disconnection urgency (e.g., "Bijli vibhag disconnection tonight unless bill is paid")
- Income Tax refund fraud / fake IT department imposter lures
- Fake UPI / QR code payment requests / lottery / KBC prize frauds
- EPFO / PF withdrawal or pension phishing
- India Post / courier parcel customs clearance fees
- Trai / SIM card deactivation alerts

Pre-scan language hint: {script_hint}

Return ONLY a valid JSON object with exactly these fields:
{{
  "detected_language": "<Language name, e.g. 'Hindi (हिन्दी)', 'Tamil (தமிழ்)', 'Bengali (বাংলা)', 'Telugu (తెలుగు)', 'Marathi (मराठी)', 'Gujarati (ગુજરાતી)', 'Kannada (ಕನ್ನಡ)', 'Malayalam (മലയാളം)', 'Punjabi (ਪੰਜਾਬੀ)', 'Odia (ଓଡ଼ିଆ)', 'Urdu (اردو)', 'Hinglish', 'English', etc.>",
  "language_code": "<Code, e.g. 'hi', 'ta', 'bn', 'te', 'mr', 'gu', 'kn', 'ml', 'pa', 'or', 'ur', 'hinglish', 'en'>",
  "is_indian_language": <true if native Indian language or Hinglish, else false>,
  "english_translation": "<brief 1-2 sentence English summary of the message body, especially if non-English>",
  "threat_score": <float between 0.0 and 1.0>,
  "threat_type": "<one of: phishing, social_engineering, malware_lure, suspicious, legitimate>",
  "reasoning": ["<bullet 1 explaining threat indicators in English>", "<bullet 2>", ...],
  "suspicious_phrases": ["<exact quote from email in original language with brief English meaning>"]
}}

Guidelines:
- threat_score 0.0 = definitely legitimate, 1.0 = definite phishing/attack
- reasoning: max 5 bullet points explaining your assessment in clear English
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
    detected_language: str = "English"
    language_code: str = "en"
    is_indian_language: bool = False
    english_translation: Optional[str] = None
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

    detected_language = str(data.get("detected_language") or "English").strip()
    language_code = str(data.get("language_code") or "en").strip().lower()
    is_indian_language = bool(data.get("is_indian_language", False))
    english_translation = data.get("english_translation")
    if english_translation:
        english_translation = str(english_translation).strip()

    return {
        "threat_score": score,
        "threat_type": threat_type,
        "reasoning": reasoning,
        "suspicious_phrases": phrases,
        "detected_language": detected_language,
        "language_code": language_code,
        "is_indian_language": is_indian_language,
        "english_translation": english_translation,
    }


def _heuristic_fallback_analysis(
    from_header: str,
    subject: str,
    body: str,
    lang_hint: Any,
    error_reason: str,
) -> LLMResult:
    """Rule-based heuristic fallback if Gemini LLM is unavailable or rate-limited.

    Prevents critical scams and phishing emails from being silently marked as Safe (0.0).
    """
    text = f"{subject} {body}".lower()

    # 1. High-confidence lottery / prize / advance-fee scam lures
    lottery_patterns = [
        r'\blottery\b', r'\blaatri\b', r'ਲਾਟਰੀ', r'लॉटरी', r'লটারি',
        r'\bprize\s+award\b', r'\bwon\b.*\b(crore|lakh|₹|\$)\b',
        r'₹\s*10[,0-9]+', r'\bbugatti\b', r'\bwinner\s+id\b',
        r'\bcongratulations.*selected\b', r'\bclaim\s+your\s+prize\b',
        r'\bunclaimed\s+(prize|funds|lottery)\b', r'\blucky\s+draw\b'
    ]
    is_lottery = any(re.search(pat, text, re.IGNORECASE) for pat in lottery_patterns)

    # 2. Banking / KYC / PAN-Aadhaar / deactivation lures
    kyc_patterns = [
        r'\bkyc\b.*(deactivat|block|suspend|update)',
        r'pan.*aadhaar.*link',
        r'bijli\s+vibhag.*disconnect',
        r'electricity\s+bill.*(power\s+cut|disconnection)',
        r'account.*(suspended|blocked).*urgent',
        r'income\s+tax\s+refund.*(claim|approved)',
    ]
    is_kyc = any(re.search(pat, text, re.IGNORECASE) for pat in kyc_patterns)

    is_free_mailer = any(domain in from_header.lower() for domain in ['@gmail.com', '@yahoo.com', '@hotmail.com', '@outlook.com'])

    if is_lottery:
        reasoning = [
            "Content matches high-confidence lottery/prize advance-fee scam lures (e.g. prize notification, cash award or sweepstake hook).",
            "Sent from personal or unverified email address inconsistent with official prize or lottery operators." if is_free_mailer else "Automated heuristic detection flagged prize lure pattern.",
            f"Heuristic safety engine applied (AI engine fallback: {error_reason[:60]}).",
        ]
        matched_phrases = [p for p in ["Lottery", "Prize Award", "Bugatti", "Winner", "₹10,00,000", "ਲਾਟਰੀ"] if p.lower() in text]
        return LLMResult(
            score=0.85,
            threat_type="phishing",
            reasoning=reasoning,
            suspicious_phrases=matched_phrases or ["Lottery lure detected"],
            detected_language=lang_hint.likely_language,
            language_code=lang_hint.language_code,
            is_indian_language=lang_hint.is_indian_native,
            available=False,
            evidence={"fallback": "heuristic_lottery_scam", "error": error_reason},
        )

    if is_kyc:
        reasoning = [
            "Content matches urgency-based credential or account deactivation / KYC phishing patterns.",
            f"Heuristic safety engine applied (AI engine fallback: {error_reason[:60]}).",
        ]
        return LLMResult(
            score=0.85,
            threat_type="phishing",
            reasoning=reasoning,
            suspicious_phrases=["KYC / Urgent Account Alert"],
            detected_language=lang_hint.likely_language,
            language_code=lang_hint.language_code,
            is_indian_language=lang_hint.is_indian_native,
            available=False,
            evidence={"fallback": "heuristic_kyc_phishing", "error": error_reason},
        )

    if (not subject.strip() or subject.strip() == "(no subject)") and len(body.strip().split()) <= 2:
        return LLMResult(
            score=0.45,
            threat_type="suspicious",
            reasoning=[
                "Email has no subject line and an ultra-brief body, typical of email address reconnaissance or probe attempts.",
                f"Heuristic fallback applied (AI engine fallback: {error_reason[:60]}).",
            ],
            detected_language=lang_hint.likely_language,
            language_code=lang_hint.language_code,
            is_indian_language=lang_hint.is_indian_native,
            available=False,
            evidence={"fallback": "heuristic_probe", "error": error_reason},
        )

    return LLMResult(
        score=0.0,
        threat_type="unknown",
        reasoning=[],
        detected_language=lang_hint.likely_language,
        language_code=lang_hint.language_code,
        is_indian_language=lang_hint.is_indian_native,
        available=False,
        evidence={"error": error_reason},
    )


async def score_llm(msg: Message) -> LLMResult:
    """Run LLM-based content analysis on the email.

    Fail-safe: applies heuristic rule engine if LLM is unavailable or quota-limited.
    """
    settings = get_settings()

    from_header = msg.get("From", "(unknown)")
    subject = msg.get("Subject", "(no subject)")
    date = msg.get("Date", "(unknown)")
    body = _extract_text_body(msg)

    # 1. Pre-detect language and script hints
    lang_hint = detect_indian_language_hint(f"{subject} {body}")
    script_hint = lang_hint.details or "Standard Latin alphabet"
    if lang_hint.is_indian_native:
        script_hint += f" (Likely {lang_hint.likely_language})"

    if not settings.GEMINI_API_KEY:
        logger.warning("GEMINI_API_KEY not set — skipping LLM analysis")
        return LLMResult(
            score=0.0,
            threat_type="unknown",
            detected_language=lang_hint.likely_language,
            language_code=lang_hint.language_code,
            is_indian_language=lang_hint.is_indian_native,
            available=False,
            evidence={"reason": "GEMINI_API_KEY not configured", "script_hint": script_hint},
        )

    if not body.strip():
        logger.warning("Empty email body — skipping LLM analysis")
        return LLMResult(
            score=0.1,
            threat_type="suspicious",
            reasoning=["Email has no readable body content"],
            detected_language=lang_hint.likely_language,
            language_code=lang_hint.language_code,
            is_indian_language=lang_hint.is_indian_native,
            evidence={"reason": "Empty body", "script_hint": script_hint},
        )

    prompt = LLM_PROMPT_TEMPLATE.format(
        script_hint=script_hint,
        from_header=from_header,
        subject=subject,
        date=date,
        body=body,
    )

    import asyncio

    try:
        import google.generativeai as genai

        genai.configure(api_key=settings.GEMINI_API_KEY)
        configured_model = getattr(settings, "GEMINI_MODEL", "gemini-flash-latest") or "gemini-flash-latest"
        candidate_models = [configured_model]
        for fallback in ["gemini-flash-latest", "gemini-2.0-flash", "gemini-1.5-flash"]:
            if fallback not in candidate_models:
                candidate_models.append(fallback)

        response = None
        last_error = None
        loop = asyncio.get_event_loop()

        for m_name in candidate_models:
            for retry_attempt in range(2):
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
                    err_str = str(exc)
                    if "429" in err_str or "ResourceExhausted" in err_str or "quota" in err_str.lower():
                        logger.warning("Gemini 429 quota on %s (attempt %d): %s", m_name, retry_attempt, exc)
                        await asyncio.sleep(1.5 * (retry_attempt + 1))
                    else:
                        logger.warning("Gemini model %s failed: %s, trying fallback", m_name, exc)
                        break

            if response and response.text:
                break

        if not response or not response.text:
            raise last_error or RuntimeError("All Gemini candidate models failed")

        raw_text = response.text
        parsed = _parse_llm_response(raw_text)

        final_lang = parsed.get("detected_language") or "English"
        final_code = parsed.get("language_code") or "en"
        final_is_indian = parsed.get("is_indian_language", False)

        # Fallback if text has Indic script but LLM genericized as English
        if lang_hint.is_indian_native and (final_lang.lower() in ("english", "unknown") or final_code in ("en", "unknown")):
            final_lang = lang_hint.likely_language
            final_code = lang_hint.language_code
            final_is_indian = True

        logger.info(
            "LLM analysis: type=%s score=%.2f language=%s (%s)",
            parsed["threat_type"], parsed["threat_score"], final_lang, final_code,
        )

        return LLMResult(
            score=parsed["threat_score"],
            threat_type=parsed["threat_type"],
            reasoning=parsed["reasoning"],
            suspicious_phrases=parsed["suspicious_phrases"],
            detected_language=final_lang,
            language_code=final_code,
            is_indian_language=final_is_indian,
            english_translation=parsed.get("english_translation"),
            available=True,
            evidence={"raw_prompt_chars": len(prompt), "body_chars": len(body), "script_hint": script_hint},
        )

    except json.JSONDecodeError as exc:
        logger.error("LLM returned invalid JSON: %s", exc)
        return _heuristic_fallback_analysis(
            from_header=from_header,
            subject=subject,
            body=body,
            lang_hint=lang_hint,
            error_reason=f"JSON parse failure: {exc}",
        )
    except Exception as exc:
        logger.error("LLM analysis failed: %s", exc)
        return _heuristic_fallback_analysis(
            from_header=from_header,
            subject=subject,
            body=body,
            lang_hint=lang_hint,
            error_reason=str(exc),
        )

