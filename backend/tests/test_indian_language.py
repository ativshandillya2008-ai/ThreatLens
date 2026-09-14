"""Tests for Indian Native Language detection, forensic heuristics, and LLM analysis."""
from __future__ import annotations

import email
from email.message import EmailMessage
import pytest
from unittest.mock import AsyncMock, patch

from backend.pipeline.language_detector import detect_indian_language_hint, SCRIPT_PATTERNS
from backend.pipeline.llm_analyzer import _parse_llm_response, score_llm, LLMResult
from backend.threats.models import ThreatScore
from backend.threats.router import _score_to_dict


def test_devanagari_hindi_detection():
    text = "प्रिय ग्राहक, आपका एसबीआई बैंक खाता बंद कर दिया गया है। तुरंत केवाईसी अपडेट करें।"
    hint = detect_indian_language_hint(text)
    assert hint.is_indian_native is True
    assert "Devanagari" in hint.script_name
    assert "Hindi" in hint.likely_language
    assert hint.language_code == "hi"


def test_bengali_detection():
    text = "জরুরি বিজ্ঞপ্তি: আপনার বিদ্যুৎ সংযোগ আজ রাতে বিচ্ছিন্ন করা হবে। অবিলম্বে বিল পরিশোধ করুন।"
    hint = detect_indian_language_hint(text)
    assert hint.is_indian_native is True
    assert "Bengali" in hint.script_name
    assert "Bengali" in hint.likely_language
    assert hint.language_code == "bn"


def test_tamil_detection():
    text = "முக்கிய அறிவிப்பு: உங்கள் வங்கி கணக்கு தற்காலிகமாக முடக்கப்பட்டுள்ளது. உடனடியாக சரிபார்க்கவும்."
    hint = detect_indian_language_hint(text)
    assert hint.is_indian_native is True
    assert "Tamil" in hint.script_name
    assert "Tamil" in hint.likely_language
    assert hint.language_code == "ta"


def test_telugu_detection():
    text = "ముఖ్య గమనిక: మీ విద్యుత్ బిల్లు చెల్లించకపోతే నేటి రాత్రి విద్యుత్ సరఫరా నిలిపివేయబడుతుంది."
    hint = detect_indian_language_hint(text)
    assert hint.is_indian_native is True
    assert "Telugu" in hint.script_name
    assert "Telugu" in hint.likely_language
    assert hint.language_code == "te"


def test_gujarati_detection():
    text = "મહત્વપૂર્ણ સૂચના: તમારા બેંક ખાતાનું કેવાયસી બાકી છે. તુરંત અપડેટ કરો."
    hint = detect_indian_language_hint(text)
    assert hint.is_indian_native is True
    assert "Gujarati" in hint.script_name
    assert "Gujarati" in hint.likely_language
    assert hint.language_code == "gu"


def test_kannada_detection():
    text = "ತುರ್ತು ಸೂಚನೆ: ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಖಾತೆಯನ್ನು ನಿರ್ಬಂಧಿಸಲಾಗಿದೆ. ತಕ್ಷಣ ಕೆವೈಸಿ ಅಪ್‌ಡೇಟ್ ಮಾಡಿ."
    hint = detect_indian_language_hint(text)
    assert hint.is_indian_native is True
    assert "Kannada" in hint.script_name
    assert "Kannada" in hint.likely_language
    assert hint.language_code == "kn"


def test_malayalam_detection():
    text = "അടിയന്തര അറിയിപ്പ്: നിങ്ങളുടെ ബാങ്ക് അക്കൗണ്ട് താൽക്കാലികമായി റദ്ദാക്കിയിരിക്കുന്നു."
    hint = detect_indian_language_hint(text)
    assert hint.is_indian_native is True
    assert "Malayalam" in hint.script_name
    assert "Malayalam" in hint.likely_language
    assert hint.language_code == "ml"


def test_gurmukhi_punjabi_detection():
    text = "ਜ਼ਰੂਰੀ ਸੂਚਨਾ: ਤੁਹਾਡਾ ਬੈਂਕ ਖਾਤਾ ਬੰਦ ਕਰ ਦਿੱਤਾ ਗਿਆ ਹੈ। ਤੁਰੰਤ ਕੇਵਾਈਸੀ ਕਰੋ।"
    hint = detect_indian_language_hint(text)
    assert hint.is_indian_native is True
    assert "Gurmukhi" in hint.script_name
    assert "Punjabi" in hint.likely_language
    assert hint.language_code == "pa"


def test_odia_detection():
    text = "ଜରୁରୀ ସୂଚନା: ଆପଣଙ୍କ ବ୍ୟାଙ୍କ ଖାତା ବନ୍ଦ ହୋଇଯିବ | ତୁରନ୍ତ KYC ଅପଡେଟ କରନ୍ତୁ |"
    hint = detect_indian_language_hint(text)
    assert hint.is_indian_native is True
    assert "Odia" in hint.script_name
    assert "Odia" in hint.likely_language
    assert hint.language_code == "or"


def test_urdu_detection():
    text = "اہم اطلاع: آپ کا بینک اکاؤنٹ بند کر دیا گیا ہے۔ فوری تصدیق کریں۔"
    hint = detect_indian_language_hint(text)
    assert hint.is_indian_native is True
    assert "Urdu" in hint.script_name
    assert "Urdu" in hint.likely_language
    assert hint.language_code == "ur"


def test_hinglish_detection():
    text = "Dear user, aapka sbi khata block ho jayega turant kyc update karein ya bijli cut ho jayegi."
    hint = detect_indian_language_hint(text)
    assert hint.is_indian_native is True
    assert "Hinglish" in hint.likely_language
    assert hint.language_code == "hinglish"


def test_english_benign_detection():
    text = "Dear Team, please find attached the quarterly financial performance metrics for Q3."
    hint = detect_indian_language_hint(text)
    assert hint.is_indian_native is False
    assert hint.likely_language == "English"
    assert hint.language_code == "en"


def test_parse_llm_response_with_indian_language():
    sample_json = """
    ```json
    {
        "detected_language": "Hindi (हिन्दी)",
        "language_code": "hi",
        "is_indian_language": true,
        "english_translation": "Your bank account has been deactivated. Complete KYC immediately.",
        "threat_score": 0.95,
        "threat_type": "phishing",
        "reasoning": ["Urgent KYC threat targeting SBI customers in Hindi"],
        "suspicious_phrases": ["आपका एसबीआई बैंक खाता बंद कर दिया गया है"]
    }
    ```
    """
    res = _parse_llm_response(sample_json)
    assert res["threat_score"] == 0.95
    assert res["threat_type"] == "phishing"
    assert res["detected_language"] == "Hindi (हिन्दी)"
    assert res["language_code"] == "hi"
    assert res["is_indian_language"] is True
    assert res["english_translation"] is not None
    assert len(res["suspicious_phrases"]) == 1


@pytest.mark.asyncio
async def test_score_llm_indic_fallback_without_api_key():
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["From"] = "sbi-kyc@alerts-fake.in"
    msg["Subject"] = "प्रिय ग्राहक, आपका एसबीआई खाता तुरंत ब्लॉक हो जाएगा"
    msg.set_content("तुरंत इस लिंक पर क्लिक करके पैन कार्ड और आधार कार्ड अपडेट करें।")

    with patch("backend.pipeline.llm_analyzer.get_settings") as mock_settings:
        mock_settings.return_value.GEMINI_API_KEY = ""
        result = await score_llm(msg)
        assert result.is_indian_language is True
        assert "Devanagari" in result.evidence.get("script_hint", "")
        assert result.language_code == "hi"



def test_threat_score_model_and_dict_serialization():
    score = ThreatScore(
        user_email="user@test.com",
        message_id="msg-12345",
        subject="बिजली बिल जमा करें",
        sender="bijli@suspicious.in",
        final_score=0.88,
        severity="HIGH",
        detected_language="Hindi (हिन्दी)",
        language_code="hi",
        llm_score=0.9,
        llm_threat_type="phishing",
    )
    score_dict = _score_to_dict(score)
    assert score_dict["detected_language"] == "Hindi (हिन्दी)"
    assert score_dict["language_code"] == "hi"
    assert score_dict["severity"] == "HIGH"
