"""Agentic AI Router — Advanced AI assistant with Gmail access, threat intelligence, and background search."""
from __future__ import annotations

import asyncio
import email
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, List, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select

from ..config import get_settings
from ..database import get_session_factory
from ..gmail.client import GmailClient
from ..pipeline.llm_analyzer import _extract_text_body
from ..pipeline.runner import run_pipeline
from ..pipeline.safe_browsing import _extract_urls
from ..threats.models import AuditOverride, ThreatScore
from ..threats.quarantine import quarantine_message, release_from_quarantine

logger = logging.getLogger(__name__)
router = APIRouter()

SYSTEM_INSTRUCTION = """You are ThreatLens Agent, a premier email security analyst and AI intelligence assistant with direct access to the user's Gmail mailbox, the ThreatLens Forensic Threat Engine, and real-time background search capabilities.

Your core capabilities and responsibilities:

1. **Inbox & Email Intelligence**:
   - When the user asks to find specific emails, find a person's messages, or search for emails on any topic (e.g. "find emails from LinkedIn", "find receipt for Spotify", "show me urgent emails"):
     - Always use `search_emails` with appropriate queries (e.g. keywords, sender domain, subject, or dates).
     - Always report **every relevant email found**, providing its Message ID, Subject, From, Date, Threat Score/Severity, and Snippet.
   - When asked to "Fetch the most recent email and provide a forensic threat assessment" or "Analyze latest email":
     1. First, call `search_emails(max_results=1)` or `list_recent_emails(max_results=1)` to locate the newest email.
     2. Next, immediately call `get_email_and_analyze_threat(message_id)` on that message's ID to run/fetch the complete threat report.
     3. Present a comprehensive, highly organized Forensic Threat Assessment Report with:
        - 📋 **Email Header Metadata**: Subject, Sender, Date, Message ID
        - 🛡️ **Forensic Verdict & Severity**: Severity level (LOW / MEDIUM / HIGH), Final Threat Score (0–100%), and quarantine status
        - 🔑 **Authentication Integrity**: SPF, DKIM, and DMARC verification results
        - 🌐 **Origin & Network Routing**: Sender Country, ASN, Organization, and Geolocation Mismatch check
        - 🔍 **AI Threat Heuristics**: Category (e.g. Phishing, Malware Lure, Legitimate), suspicious phrases, urgency lures, and detailed reasoning
        - 🔗 **Hyperlinks & URL Safety**: Google Safe Browsing results and malicious link check
        - 💡 **Actionable Recommendation**: Clear next steps (Safe to interact, Quarantine, or secondary verification).
   - When the user asks for the full content of an email, use `get_email_full_content` to read its actual headers, plain text body, and links.
   - Use `summarize_email` to produce executive summaries.
   - Use `quarantine_or_release_email` to quarantine threats or release false positives.
   - Use `draft_safe_reply` or `send_email` when asked to prepare or send responses.

2. **Mastery of Cybersecurity & Cybercrime**:
   - You have deep, authoritative knowledge in all areas of Cybersecurity, Cybercrime, Threat Intelligence, and Digital Forensics, including:
     - Phishing, Spear-Phishing, Whaling, Business Email Compromise (BEC), CEO Fraud, and invoice fraud.
     - Ransomware strains, extortion tactics, data exfiltration, supply chain attacks, and initial access brokers.
     - Social engineering psychology, credential harvesting, OAuth consent abuse, EvilProxy/AitM session hijacking.
     - Email authentication architecture (SPF, DKIM, DMARC, ARC, BIMI, MTA-STS).
     - Network forensics, GeoIP anomalies, BGP routing anomalies, reverse DNS, and MX record spoofing.
     - Known threat actor groups (APTs, cybercrime syndicates), MITRE ATT&CK techniques, and zero-day vulnerabilities/CVEs.

3. **Universal Questions & Out-of-Topic Inquiries**:
   - When the user asks general, technical, or out-of-topic questions (e.g. programming, science, history, current events, daily advice):
     - **NEVER** refuse to answer.
     - **NEVER** give an error or state that you can only discuss emails.
     - Answer clearly, helpfully, accurately, and politely.
   - When real-time, current (2026), or latest information is required (such as today's cybersecurity incidents, recent CVEs, live news, or external technical data), use `search_web_and_cybersecurity_intelligence` to perform a background search and synthesize a fresh, accurate response.

Style Guidelines:
- Format your responses using clean GitHub Markdown with clear headers, bullet points, and code/quote blocks where appropriate.
- Be proactive, intelligent, concise, and professional.
- When an email contains high-risk indicators or malicious links, explicitly warn the user not to click links or execute attachments.
"""


class ChatMessage(BaseModel):
    role: str  # "user" | "assistant"
    content: str


class AgentChatRequest(BaseModel):
    messages: List[ChatMessage]


@router.post("/chat")
async def agent_chat(request: Request, body: AgentChatRequest) -> JSONResponse:
    """Conversational endpoint for the Agentic AI."""
    user_email = request.session.get("user_email")
    if not user_email:
        return JSONResponse({
            "response": (
                "**Gmail Account Not Connected**\n\n"
                "Please connect your Gmail account first using the **Connect Gmail Account** button. "
                "Once connected, I will have access to your mailbox to analyze incoming emails, detect phishing threats, "
                "summarize messages, and help you draft safe replies."
            ),
            "tools_called": [],
            "authenticated": False,
        })

    settings = get_settings()
    if not settings.GEMINI_API_KEY:
        raise HTTPException(status_code=500, detail="GEMINI_API_KEY is not configured on the server.")

    loop = asyncio.get_running_loop()
    tools_called: List[dict[str, Any]] = []

    # ── Define Tools Available to the Agent ─────────────────────────────────

    def search_emails(query: str = "", max_results: int = 20) -> str:
        """Search the user's Gmail mailbox matching an optional query string (e.g. from:sender, subject keywords, or plain text search).
        Returns all matching messages with Message ID, sender, subject, date, threat severity score, and snippet.
        """
        tools_called.append({"tool": "search_emails", "query": query, "max_results": max_results})

        async def _fetch():
            try:
                num = int(float(max_results)) if max_results is not None else 20
            except (ValueError, TypeError):
                num = 20
            clean_limit = max(1, min(num, 25))

            try:
                async with GmailClient(user_email) as client:
                    data = await client.list_messages(query=query, max_results=clean_limit)
                messages = data.get("messages", [])
                if not messages:
                    return f"No emails found matching query: '{query}'."

                msg_ids = [m["id"] for m in messages]
                factory = get_session_factory()
                async with factory() as session:
                    res = await session.execute(
                        select(ThreatScore).where(
                            ThreatScore.message_id.in_(msg_ids),
                            ThreatScore.user_email == user_email,
                        )
                    )
                    scores = {r.message_id: r for r in res.scalars().all()}

                async with GmailClient(user_email) as client:
                    async def _get_meta(m):
                        try:
                            meta = await client.get_message(m["id"], format="metadata")
                            headers = {h["name"].lower(): h["value"] for h in meta.get("payload", {}).get("headers", [])}
                            score_rec = scores.get(m["id"])
                            if score_rec:
                                threat_label = f"Score: {int(score_rec.final_score * 100)}% ({score_rec.severity})"
                                if score_rec.quarantined:
                                    threat_label += " [QUARANTINED]"
                            else:
                                threat_label = "Unanalyzed (Pending Scan)"

                            return (
                                f"• Message ID: {m['id']}\n"
                                f"  From: {headers.get('from', 'Unknown')}\n"
                                f"  Subject: {headers.get('subject', '(No Subject)')}\n"
                                f"  Date: {headers.get('date', 'Unknown')}\n"
                                f"  Threat Assessment: {threat_label}\n"
                                f"  Snippet: {meta.get('snippet', '')}\n"
                            )
                        except Exception as e:
                            logger.warning("Error getting metadata for %s: %s", m["id"], e)
                            return f"• Message ID: {m['id']} (Error fetching metadata)"

                    meta_tasks = [_get_meta(m) for m in messages]
                    results = await asyncio.gather(*meta_tasks)

                return "\n".join(results) if results else "Failed to retrieve email details."
            except Exception as exc:
                logger.error("Error in search_emails: %s", exc)
                return f"Could not search emails due to error: {str(exc)}"

        return asyncio.run_coroutine_threadsafe(_fetch(), loop).result()

    def list_recent_emails(query: str = "", max_results: int = 10) -> str:
        """Fetch a list of recent emails from the user's Gmail matching an optional query.
        Returns message IDs, sender, subject, date, snippet, and threat status.
        """
        return search_emails(query=query, max_results=max_results)

    def get_email_full_content(message_id: str) -> str:
        """Retrieve the full content, headers, plain text body, and links of a specific email by Message ID.
        Use this to read and answer detailed questions about the contents of an email.
        """
        tools_called.append({"tool": "get_email_full_content", "message_id": message_id})

        async def _get_full():
            try:
                async with GmailClient(user_email) as client:
                    raw_bytes = await client.get_raw_message(message_id)

                msg = email.message_from_bytes(raw_bytes)
                body = _extract_text_body(msg)
                urls = _extract_urls(msg)

                return (
                    f"=== Full Email Content ===\n"
                    f"Message ID: {message_id}\n"
                    f"Subject: {msg.get('Subject', '(No Subject)')}\n"
                    f"From: {msg.get('From', 'Unknown')}\n"
                    f"To: {msg.get('To', 'Unknown')}\n"
                    f"Date: {msg.get('Date', 'Unknown')}\n"
                    f"Embedded Links: {urls[:10] if urls else 'None'}\n\n"
                    f"Body Content:\n{body[:3500]}"
                )
            except Exception as exc:
                logger.error("Error getting full email content for %s: %s", message_id, exc)
                return f"Could not retrieve email body due to error: {str(exc)}"

        return asyncio.run_coroutine_threadsafe(_get_full(), loop).result()

    def get_email_and_analyze_threat(message_id: str) -> str:
        """Perform full forensic threat inspection on a specific email.
        Runs SPF/DKIM/DMARC validation, IP geolocation, Safe Browsing URL check, and AI reasoning.
        """
        tools_called.append({"tool": "get_email_and_analyze_threat", "message_id": message_id})

        async def _analyze():
            try:
                factory = get_session_factory()
                async with factory() as session:
                    res = await session.execute(
                        select(ThreatScore).where(
                            ThreatScore.message_id == message_id,
                            ThreatScore.user_email == user_email,
                        )
                    )
                    score_rec = res.scalar_one_or_none()

                # If not yet scored, run the pipeline
                if not score_rec:
                    try:
                        score_rec = await run_pipeline(user_email, message_id)
                    except Exception as e:
                        logger.error("Pipeline run failed for %s: %s", message_id, e)

                async with GmailClient(user_email) as client:
                    full_msg = await client.get_message(message_id, format="full")

                headers = {h["name"].lower(): h["value"] for h in full_msg.get("payload", {}).get("headers", [])}

                if not score_rec:
                    return (
                        f"Email details:\n"
                        f"Subject: {headers.get('subject')}\n"
                        f"From: {headers.get('from')}\n"
                        f"Date: {headers.get('date')}\n"
                        f"Snippet: {full_msg.get('snippet')}\n"
                        f"(Threat scoring pipeline could not be completed for this message)."
                    )

                return (
                    f"=== Threat Forensic Report ===\n"
                    f"Subject: {score_rec.subject}\n"
                    f"From: {score_rec.sender}\n"
                    f"Severity: {score_rec.severity} (Final Threat Score: {score_rec.final_score * 100:.1f}%)\n"
                    f"Quarantined in Gmail: {score_rec.quarantined}\n"
                    f"Authentication: SPF={score_rec.spf_result}, DKIM={score_rec.dkim_result}, DMARC={score_rec.dmarc_result}\n"
                    f"Origin Country: {score_rec.geo_country or 'Unknown'} (ASN: {score_rec.geo_asn or 'N/A'})\n"
                    f"Geo-Mismatch Flag: {score_rec.geo_mismatch}\n"
                    f"AI Threat Category: {score_rec.llm_threat_type}\n"
                    f"AI Reasoning: {score_rec.llm_reasoning}\n"
                    f"Flagged Phrases: {score_rec.llm_suspicious_phrases}\n"
                    f"URLs Scanned: {score_rec.urls_checked}\n"
                    f"Unsafe URLs Found: {score_rec.unsafe_urls}\n"
                )
            except Exception as exc:
                logger.error("Error analyzing email threat %s: %s", message_id, exc)
                return f"Could not analyze email threat due to error: {str(exc)}"

        return asyncio.run_coroutine_threadsafe(_analyze(), loop).result()

    def summarize_email(message_id: str) -> str:
        """Fetch and return an executive summary of an email's content and intent."""
        tools_called.append({"tool": "summarize_email", "message_id": message_id})

        async def _summarize():
            try:
                async with GmailClient(user_email) as client:
                    full_msg = await client.get_message(message_id, format="full")
                headers = {h["name"].lower(): h["value"] for h in full_msg.get("payload", {}).get("headers", [])}
                return (
                    f"Subject: {headers.get('subject')}\n"
                    f"From: {headers.get('from')}\n"
                    f"Snippet: {full_msg.get('snippet')}\n"
                )
            except Exception as exc:
                logger.error("Error summarizing email %s: %s", message_id, exc)
                return f"Could not summarize email due to error: {str(exc)}"

        return asyncio.run_coroutine_threadsafe(_summarize(), loop).result()

    def search_web_and_cybersecurity_intelligence(query: str) -> str:
        """Search the web in the background for real-time cyber threats, recent security advisories, CVEs, or any present-time or general topic.
        Returns summaries and snippets from top search results.
        """
        tools_called.append({"tool": "search_web_and_cybersecurity_intelligence", "query": query})
        try:
            import httpx
            from bs4 import BeautifulSoup

            clean_q = query.strip()
            resp = httpx.get(
                "https://html.duckduckgo.com/html/",
                params={"q": clean_q},
                headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
                timeout=7.0,
                follow_redirects=True,
            )
            if resp.status_code != 200:
                return f"Search engine returned status code {resp.status_code} for query '{query}'."

            soup = BeautifulSoup(resp.text, "html.parser")
            snippets = []
            for s in soup.find_all("a", class_="result__snippet", limit=5):
                text = s.get_text(strip=True)
                if text:
                    snippets.append(f"• {text}")

            return "\n".join(snippets) if snippets else f"No search snippets found for '{query}'."
        except Exception as exc:
            logger.warning("Background search error for '%s': %s", query, exc)
            return f"Background search error: {str(exc)}"

    def quarantine_or_release_email(message_id: str, action: str) -> str:
        """Quarantine a suspicious email (moves to Quarantine label in Gmail) or release a safe email.
        Action must be 'quarantine' or 'release'.
        """
        tools_called.append({"tool": "quarantine_or_release_email", "message_id": message_id, "action": action})

        async def _act():
            try:
                if action.lower() == "quarantine":
                    await quarantine_message(user_email, message_id)
                    return f"Successfully moved email {message_id} to Quarantine in Gmail."
                elif action.lower() == "release":
                    await release_from_quarantine(user_email, message_id)
                    return f"Successfully released email {message_id} from quarantine back to Inbox."
                else:
                    return f"Unknown action: {action}. Must be 'quarantine' or 'release'."
            except Exception as exc:
                logger.error("Error modifying quarantine for %s: %s", message_id, exc)
                return f"Could not update quarantine due to error: {str(exc)}"

        return asyncio.run_coroutine_threadsafe(_act(), loop).result()

    def draft_safe_reply(to: str, subject: str, body: str) -> str:
        """Create a draft reply in the user's Gmail mailbox. The user can review it before sending."""
        tools_called.append({"tool": "draft_safe_reply", "to": to, "subject": subject})

        async def _draft():
            try:
                async with GmailClient(user_email) as client:
                    res = await client.create_draft(to=to, subject=subject, body=body)
                return f"Draft created successfully in Gmail (Draft ID: {res.get('id', 'N/A')}). You can review or edit it in your Gmail client."
            except Exception as exc:
                logger.error("Error creating draft: %s", exc)
                return f"Could not create draft due to error: {str(exc)}"

        return asyncio.run_coroutine_threadsafe(_draft(), loop).result()

    def send_email(to: str, subject: str, body: str) -> str:
        """Send an email from the user's Gmail account."""
        tools_called.append({"tool": "send_email", "to": to, "subject": subject})

        async def _send():
            try:
                async with GmailClient(user_email) as client:
                    res = await client.send_message(to=to, subject=subject, body=body)
                return f"Email successfully sent (Message ID: {res.get('id', 'N/A')})."
            except Exception as exc:
                logger.error("Error sending email: %s", exc)
                return f"Could not send email due to error: {str(exc)}"

        return asyncio.run_coroutine_threadsafe(_send(), loop).result()

    # ── Execute Agent with Gemini & Model Fallback ──────────────────────────
    try:
        import google.generativeai as genai

        genai.configure(api_key=settings.GEMINI_API_KEY)

        tools = [
            search_emails,
            list_recent_emails,
            get_email_full_content,
            get_email_and_analyze_threat,
            summarize_email,
            search_web_and_cybersecurity_intelligence,
            quarantine_or_release_email,
            draft_safe_reply,
            send_email,
        ]

        # Candidate model list with automatic fallback (prioritizing high-quota models)
        candidate_models = [
            getattr(settings, "GEMINI_MODEL", "gemini-3.5-flash") or "gemini-3.5-flash",
            "gemini-3.5-flash",
            "gemini-3.5-flash-lite",
            "gemini-3.7-flash",
            "gemini-flash-latest",
            "gemini-3.8-flash",
        ]
        unique_models = []
        for m in candidate_models:
            if m not in unique_models:
                unique_models.append(m)

        # Pre-populate history without extra API overhead
        formatted_history = []
        for msg in body.messages[:-1]:
            role = "user" if msg.role == "user" else "model"
            formatted_history.append({"role": role, "parts": [msg.content]})

        latest_prompt = body.messages[-1].content if body.messages else "Hello"

        agent_text = ""
        last_exc = None

        for model_name in unique_models:
            try:
                model = genai.GenerativeModel(
                    model_name=model_name,
                    system_instruction=SYSTEM_INSTRUCTION,
                    tools=tools,
                )
                chat = model.start_chat(
                    history=formatted_history,
                    enable_automatic_function_calling=True,
                )

                def _run_chat():
                    resp = chat.send_message(latest_prompt)
                    return resp.text

                with ThreadPoolExecutor() as executor:
                    agent_text = await loop.run_in_executor(executor, _run_chat)

                if agent_text:
                    logger.info("Agent response successfully generated using model %s", model_name)
                    break
            except Exception as exc:
                last_exc = exc
                logger.warning("Agent chat failed with model %s: %s. Trying next candidate...", model_name, exc)

        if not agent_text:
            logger.error("All agent models failed: %s", last_exc)
            agent_text = (
                "I am currently experiencing temporary service limitations with the upstream AI provider. "
                "Please try again in a few moments, or ask your question in another way."
            )

        return JSONResponse({
            "response": agent_text,
            "tools_called": tools_called,
            "authenticated": True,
        })

    except Exception as exc:
        logger.error("Agent execution top-level error: %s", exc, exc_info=True)
        return JSONResponse({
            "response": f"An error occurred while processing your request: {str(exc)}",
            "tools_called": tools_called,
            "authenticated": True,
        })
