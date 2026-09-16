# ThreatLens — AI Email Threat Detection & Forensic Intelligence

AI-powered email threat detection with real-time Gmail scanning, SPF/DKIM/DMARC validation, IP geolocation, Gemini LLM analysis, and Safe Browsing URL reputation checks.


> 🚀 **Looking to deploy online for team or public access?** See the complete [Deployment Guide](DEPLOYMENT.md) for 1-click cloud hosting (Render, Cloud Run, VPS, Cloudflare Tunnel).

---

## Quick Start (Local Dev)

### Prerequisites
- Python 3.12+
- Node.js 20+
- A Google Cloud project with these APIs enabled:
  - Gmail API
  - Google Safe Browsing API v4
  - Google AI (Gemini API)
  - Cloud Pub/Sub (for real-time push; optional for polling mode)

---

### 1. Configure credentials

```bash
cp .env.example .env
```

Edit `.env` and fill in:

| Variable | Where to get it |
|---|---|
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | [Google Cloud Console → Credentials](https://console.cloud.google.com/apis/credentials) → Create OAuth 2.0 Client ID (Web Application), add redirect URI `http://127.0.0.1:8088/auth/callback` |
| `GEMINI_API_KEY` | [Google AI Studio](https://aistudio.google.com/app/apikey) |
| `SAFE_BROWSING_API_KEY` | [Cloud Console → Safe Browsing API](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com) |
| `FERNET_KEY` | `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `SESSION_SECRET` | `python -c "import secrets; print(secrets.token_hex(32))"` |

---

### 2. Start the backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --port 8088 --reload
```

API docs at: http://127.0.0.1:8088/api/docs

---

### 3. Start the frontend (dev mode)

```bash
cd frontend
npm install
npm run dev
```

Visit: http://localhost:5173 (proxies API calls to :8088)

---

### 4. Build frontend for production (serves via FastAPI)

```bash
cd frontend
npm run build
# Now visit http://127.0.0.1:8088 — FastAPI serves the SPA directly
```

---

### 5. Set up Gmail push notifications (optional — for real-time)

Real-time processing requires a public HTTPS endpoint. For local dev:

```bash
# Install cloudflared or ngrok, then:
cloudflared tunnel --url http://127.0.0.1:8088
# or:
ngrok http 8088
```

Then set in `.env`:
```
PUBSUB_TOPIC=projects/YOUR_PROJECT/topics/gmail-push
PUBSUB_PUSH_AUDIENCE=https://your-tunnel-url.trycloudflare.com/api/pubsub/push
```

And grant `gmail-api-push@system.gserviceaccount.com` the **Pub/Sub Publisher** role on your topic.

After starting the server, visit http://127.0.0.1:8088/api/gmail/setup-watch (while logged in).

---

## Architecture

```
Browser (React SPA)
    │  OAuth2 PKCE     │  REST API
    ▼                  ▼
FastAPI :8088
    ├── /auth/*         → OAuth2 flow (PKCE, server-side exchange)
    ├── /api/gmail/*    → Gmail proxy + threat enrichment
    ├── /api/threats/*  → Threat audit log + override
    └── /api/pubsub/push → Pub/Sub push webhook (Google OIDC JWT verified)
         │
         ▼  asyncio.gather (all 4 stages concurrent)
    Pipeline Runner
    ├── SPF/DKIM/DMARC  (Authentication-Results header parser)
    ├── GeoIP           (ip-api.com / MaxMind + ESP allowlist)
    ├── LLM             (Gemini 1.5 Flash — fail-open)
    └── Safe Browsing   (Google SB v4 — fail-open)
         │
         ▼  Weighted score: auth×0.30 + geo×0.20 + llm×0.35 + url×0.15
    ThreatScore (SQLite, append-only)
         │
         ├── severity LOW  → no action
         ├── severity MEDIUM → add ⚠️ Quarantine label
         └── severity HIGH  → quarantine + interstitial before opening
```

---

## Security Model

| Concern | Mitigation |
|---|---|
| Session fixation / XSS cookie theft | `HttpOnly` session cookie (Starlette default), `SameSite=Lax`, `Secure` in prod |
| CSRF on state-changing endpoints | `X-CSRF-Token` double-submit pattern; exempt: Pub/Sub (Google JWT), OAuth (GET) |
| Authorization code interception | Server-side PKCE (S256), code_verifier never leaves the server |
| Refresh token exfiltration | Fernet-encrypted at rest in SQLite, never sent to client |
| Pub/Sub replay attacks | OIDC JWT verified: **both signature AND `aud` claim** must match |
| GeoIP false positives | ESP CIDR allowlist (SendGrid, SES, Gmail, M365, etc.); mismatch weight reduced to 0.15 |
| PII accumulation in headers | 2-phase retention: headers nulled at 30d, records deleted at 90d |
| Guest / unauthenticated access | Strictly prohibited; all routes & APIs require active Google OAuth session (`401 Unauthorized`); no guest mode |

---

## Running Tests

```bash
cd backend
pip install -r requirements.txt
pytest tests/ -v --asyncio-mode=auto
```

Test coverage:
- `test_auth.py` — PKCE generation, Fernet encryption, token exchange
- `test_pipeline.py` — All 4 pipeline stages, severity thresholds
- `test_pubsub.py` — JWT `aud` validation, issuer validation, payload decoding
- `test_override_flow.py` — CSRF protection, auth guards, override semantics

---

## Environment Variables Reference

See [`.env.example`](.env.example) for all variables with descriptions.

Key variables:

| Variable | Default | Description |
|---|---|---|
| `FERNET_KEY` | (required) | AES-128 key for refresh token encryption |
| `SESSION_SECRET` | (required, ≥32 chars) | Cookie signing key |
| `GEMINI_API_KEY` | (optional) | LLM analysis; pipeline skips stage if unset |
| `SAFE_BROWSING_API_KEY` | (optional) | URL check; pipeline skips stage if unset |
| `PUBSUB_TOPIC` | (optional) | Real-time push; polling mode used if unset |
| `PUBSUB_PUSH_AUDIENCE` | (optional) | JWT `aud` validation; set for production |
| `RETENTION_HEADERS_DAYS` | `30` | Days before raw headers are nulled |
| `RETENTION_DELETE_DAYS` | `90` | Days before full records are deleted |
| `DEBUG` | `false` | Disables `Secure` cookie flag and JWT enforcement for local dev |

---

## Data & Privacy

- **Email content** is sent to Google's Gemini API for threat analysis. See the [Gemini API Terms of Service](https://ai.google.dev/gemini-api/terms).
- **Email bodies are never stored** — only threat scores and metadata.
- **Raw email headers** are Fernet-encrypted and automatically nulled after 30 days.
- **All threat records** are deleted after 90 days.
- **Refresh tokens** are Fernet-encrypted at rest and never transmitted to the browser.

---

## Gmail Tier vs. Quarantine Behavior

| Severity | Score | Action |
|---|---|---|
| LOW | < 0.40 | No action — email stays in inbox |
| MEDIUM | 0.40–0.69 | `⚠️ Quarantine` label added; yellow warning banner in UI |
| HIGH | ≥ 0.70 | `⚠️ Quarantine` label added + `INBOX` label removed; interstitial confirmation required before opening |

The `⚠️ Quarantine` label is a custom Gmail label (red background). For MEDIUM-tier emails you may also consider enabling Gmail's native `SPAM` label instead to route them to the built-in Spam folder.
