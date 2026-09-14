"""Indian Native Language and Script Detector.

Detects Indic scripts (Devanagari, Bengali, Tamil, Telugu, Marathi, Gujarati,
Kannada, Malayalam, Punjabi, Odia, Urdu) and Romanized Hinglish/Indic transliteration.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

# Unicode script ranges for major Indian native languages
SCRIPT_PATTERNS = {
    "Devanagari (Hindi/Marathi)": (re.compile(r"[\u0900-\u097F]"), "hi", "Hindi / Marathi (हिन्दी / मराठी)"),
    "Bengali / Assamese": (re.compile(r"[\u0980-\u09FF]"), "bn", "Bengali / Assamese (বাংলা / অসমীয়া)"),
    "Tamil": (re.compile(r"[\u0B80-\u0BFF]"), "ta", "Tamil (தமிழ்)"),
    "Telugu": (re.compile(r"[\u0C00-\u0C7F]"), "te", "Telugu (తెలుగు)"),
    "Gujarati": (re.compile(r"[\u0A80-\u0AFF]"), "gu", "Gujarati (ગુજરાતી)"),
    "Kannada": (re.compile(r"[\u0C80-\u0CFF]"), "kn", "Kannada (ಕನ್ನಡ)"),
    "Malayalam": (re.compile(r"[\u0D00-\u0D7F]"), "ml", "Malayalam (മലയാളം)"),
    "Gurmukhi (Punjabi)": (re.compile(r"[\u0A00-\u0A7F]"), "pa", "Punjabi (ਪੰਜਾਬੀ)"),
    "Odia": (re.compile(r"[\u0B00-\u0B7F]"), "or", "Odia (ଓଡ଼ିଆ)"),
    "Urdu (Arabic Script)": (re.compile(r"[\u0600-\u06FF]"), "ur", "Urdu (اردو)"),
}

# Common transliterated Indic / Hinglish words often seen in phishing and alerts
HINGLISH_KEYWORDS = {
    "aapka", "aapke", "aapki", "khata", "khate", "turant", "karein", "karo", "band",
    "yojana", "bijli", "vibhag", "kripya", "suchna", "sarkari", "sudhaar", "paisey",
    "paise", "inam", "dhan", "sampark", "namaste", "namaskar", "shriman", "shrimati",
    "bheje", "deactivation", "deactivate", "shulak", "chori", "aadhar", "aadhaar",
    "rashan", "pan", "bijlee", "katoti", "sulabh", "suvidha", "suraksha",
}


@dataclass
class LanguageHint:
    script_name: Optional[str] = None
    likely_language: str = "English"
    language_code: str = "en"
    is_indian_native: bool = False
    indic_char_count: int = 0
    confidence: float = 0.0
    details: str = ""


def detect_indian_language_hint(text: str) -> LanguageHint:
    """Analyze text for Indic scripts or Hinglish vocabulary.

    Returns a LanguageHint with script classification, language candidate, and confidence.
    """
    if not text or not text.strip():
        return LanguageHint()

    clean_text = text.strip()
    total_len = max(1, len(clean_text))

    # 1. Check Unicode script character frequencies
    best_script = None
    best_code = "en"
    best_lang = "English"
    max_matches = 0

    for script_name, (regex, code, lang_label) in SCRIPT_PATTERNS.items():
        matches = len(regex.findall(clean_text))
        if matches > max_matches:
            max_matches = matches
            best_script = script_name
            best_code = code
            best_lang = lang_label

    if max_matches >= 3:
        confidence = min(1.0, max_matches / (total_len * 0.4 + 5))
        return LanguageHint(
            script_name=best_script,
            likely_language=best_lang,
            language_code=best_code,
            is_indian_native=True,
            indic_char_count=max_matches,
            confidence=round(confidence, 2),
            details=f"Native Indic script detected: {best_script} ({max_matches} characters)",
        )

    # 2. Check for Hinglish / Romanized Indic vocabulary
    words = set(re.findall(r"\b[a-zA-Z]{3,}\b", clean_text.lower()))
    hinglish_matches = words.intersection(HINGLISH_KEYWORDS)

    if len(hinglish_matches) >= 2:
        return LanguageHint(
            script_name="Latin (Hinglish/Transliterated)",
            likely_language="Hinglish (Hindi-English)",
            language_code="hinglish",
            is_indian_native=True,
            indic_char_count=len(hinglish_matches),
            confidence=0.85,
            details=f"Transliterated Indic vocabulary identified: {', '.join(sorted(hinglish_matches)[:4])}",
        )

    return LanguageHint(
        script_name="Latin",
        likely_language="English",
        language_code="en",
        is_indian_native=False,
        confidence=0.95,
        details="Standard Latin alphabet",
    )
