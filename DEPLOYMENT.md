# ThreatLens — Production & Cloud Deployment Guide

This guide explains how to deploy **ThreatLens** to the cloud or public internet so that other users (team members, clients, or security analysts) can access and use it securely.

---

## Architecture Overview

ThreatLens is designed as a unified full-stack application:
- **Frontend**: React + TypeScript SPA (compiled into `frontend/dist`).
- **Backend**: FastAPI (Python 3.12) with asynchronous SQLAlchemy, SQLite storage, and uvicorn.
- **Single Service**: FastAPI serves both the REST API/OAuth routes and the static compiled frontend bundle on the same port. No separate frontend web server is required.

```
┌─────────────────────────────────────────────────────────────┐
│                 Internet / Users (Browser)                  │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTPS (Port 443)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│             Reverse Proxy / Cloud Edge (SSL)                │
│    (Render / Cloud Run / Nginx / Cloudflare Tunnel)         │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP (Port 8088 or $PORT)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                    ThreatLens Container                     │
│  FastAPI (API + Pub/Sub Webhook + Serves React SPA)         │
│  SQLite Database + Google APIs + Gemini Intelligence        │
└─────────────────────────────────────────────────────────────┘
```

---

## Step 0: Essential Google Cloud & OAuth Configuration

Because ThreatLens uses Google OAuth 2.0 to authenticate users and inspect emails, **Google requires HTTPS and explicit authorized URLs for any public deployment**.

### 1. Configure the OAuth Consent Screen (Universal Public Access)
1. Go to [Google Cloud Console → APIs & Services → OAuth consent screen](https://console.cloud.google.com/apis/credentials/consent).
2. Choose **External** (this allows anyone with a Google account to use the website).
3. Fill in:
   - **App name**: `ThreatLens`
   - **User support email**: Your email
   - **Developer contact information**: Your email
4. **Publishing Status ("Anyone can use my website")**:
   - **While "In Testing"**: Only users explicitly listed under **Test Users** can sign in! If any other person tries to log in, Google returns Error 403 `access_denied`.
   - **To allow ANY user on the internet to sign in**: Click **Publish App** (status changes to **In Production**).
   - Once published, anyone with a Google account can sign in. When users encounter Google's standard "Google hasn't verified this app" warning, they simply click **"Advanced" → "Go to ThreatLens (unsafe)"** and grant access.
   - **No Guest Mode**: ThreatLens strictly operates on authenticated live mailboxes. Users must sign in with Google to use the application.

### 2. Configure Authorized Redirect URIs
1. Go to [Google Cloud Console → APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials).
2. Click on your **Web client** OAuth 2.0 Client ID.
3. Under **Authorized JavaScript origins**, add your deployment domain:
   ```
   https://threatlens.yourdomain.com
   ```
4. Under **Authorized redirect URIs**, add the exact callback path:
   ```
   https://threatlens.yourdomain.com/auth/callback
   ```
5. Click **Save**.

### 3. Generate Required Security Keys
Before deploying, generate your encryption and session secrets in your terminal:
```bash
# Generate Fernet token encryption key
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Generate Session secret key (must be at least 32 characters)
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## Deployment Options

Select the method that best matches your infrastructure:

| Option | Best For | Setup Time | Cost |
|---|---|---|---|
| **Option 1: Render / Railway** | Fast, hassle-free cloud hosting with free SSL | 5 mins | Free tier / $5/mo |
| **Option 2: Cloudflare Tunnel** | Instant remote access directly from local machine | 2 mins | 100% Free |
| **Option 3: Cloud VPS (Docker + Nginx)** | Full control, persistent SQLite, custom domain | 15 mins | $4–$6/mo |
| **Option 4: Google Cloud Run** | Serverless GCP native scaling & Pub/Sub integration | 10 mins | Pay per request |

---

## Option 1: Render.com (Recommended — Quickest Cloud Hosting)

Render automatically builds Docker containers and assigns a free `https://<app>.onrender.com` domain with automatic SSL.

1. **Push your code to GitHub** (if not already done).
2. Log into [Render.com](https://render.com) and click **New +** → **Web Service**.
3. Select your GitHub repository.
4. Configure service settings:
   - **Name**: `threatlens`
   - **Runtime**: `Docker`
   - **Dockerfile Path**: `Dockerfile`
   - **Instance Type**: `Free` or `Starter` ($7/mo recommended for persistent memory).
5. In **Environment Variables**, add:
   ```ini
   ENVIRONMENT=production
   DEBUG=False
   FERNET_KEY=<your-generated-fernet-key>
   SESSION_SECRET=<your-generated-session-secret>
   GOOGLE_CLIENT_ID=<your-google-client-id>
   GOOGLE_CLIENT_SECRET=<your-google-client-secret>
   OAUTH_REDIRECT_URI=https://<your-render-subdomain>.onrender.com/auth/callback
   GEMINI_API_KEY=<your-gemini-api-key>
   SAFE_BROWSING_API_KEY=<your-safe-browsing-api-key>
   GEOIP_USE_IPAPI=True
   ```
6. Click **Create Web Service**. Render will automatically build the multi-stage Docker image and start the server.
7. Once deployed, copy your Render URL (`https://<app>.onrender.com`), go to Google Cloud Console, and add `https://<app>.onrender.com/auth/callback` to your **Authorized redirect URIs**.

---

## Option 2: Instant Remote Access via Cloudflare Tunnel (No Cloud Server Required)

If you already have ThreatLens running locally and want to share it with someone remotely right now:

1. **Start the production server locally**:
   ```bash
   cd frontend && npm run build && cd ..
   ./.venv/bin/uvicorn backend.main:app --host 127.0.0.1 --port 8088
   ```
2. **Create a Cloudflare Tunnel** (free, public HTTPS):
   ```bash
   # Install cloudflared (macOS: brew install cloudflared / Linux: apt install cloudflared)
   cloudflared tunnel --url http://127.0.0.1:8088
   ```
3. Cloudflare will output a temporary public HTTPS link (e.g., `https://random-words.trycloudflare.com`).
4. In Google Cloud Console:
   - Add `https://random-words.trycloudflare.com` to **Authorized JavaScript origins**.
   - Add `https://random-words.trycloudflare.com/auth/callback` to **Authorized redirect URIs**.
5. Update `OAUTH_REDIRECT_URI=https://random-words.trycloudflare.com/auth/callback` in `.env` and restart the backend.
6. Anyone with that link can now access your ThreatLens instance from anywhere in the world!

---

## Option 3: VPS / Dedicated Server (DigitalOcean, AWS EC2, Hetzner, Linode)

For full server control with Docker Compose, Nginx, and automated Let's Encrypt SSL:

### 1. Install Docker on your VPS
```bash
sudo apt update && sudo apt install -y docker.io docker-compose git nginx certbot python3-certbot-nginx
```

### 2. Clone and Configure
```bash
git clone https://github.com/<your-username>/ThreatLens.git /opt/threatlens
cd /opt/threatlens
cp .env.example .env
nano .env  # Enter your production keys and domain
```

### 3. Start ThreatLens Container
```bash
docker compose up -d --build
```

### 4. Configure Nginx Reverse Proxy
Create `/etc/nginx/sites-available/threatlens`:
```nginx
server {
    server_name threatlens.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8088;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

Enable site and provision free SSL:
```bash
sudo ln -s /etc/nginx/sites-available/threatlens /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d threatlens.yourdomain.com
```

---

## Option 4: Google Cloud Run (Serverless Container)

If you prefer Google's serverless infrastructure:

1. Build and push image:
   ```bash
   gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/threatlens .
   ```
2. Deploy to Cloud Run:
   ```bash
   gcloud run deploy threatlens \
     --image gcr.io/YOUR_PROJECT_ID/threatlens \
     --platform managed \
     --region us-central1 \
     --allow-unauthenticated \
     --port 8088 \
     --set-env-vars "ENVIRONMENT=production,DEBUG=False,FERNET_KEY=...,SESSION_SECRET=...,GOOGLE_CLIENT_ID=...,GOOGLE_CLIENT_SECRET=...,OAUTH_REDIRECT_URI=https://<service-url>/auth/callback,GEMINI_API_KEY=...,SAFE_BROWSING_API_KEY=..."
   ```

---

## Pre-Flight Verification Checklist

Before sharing your deployed link with others:
- [ ] **HTTPS Active**: Ensure access is over `https://`. Session cookies require secure transport in production.
- [ ] **Google Redirect URI matches**: Check that `OAUTH_REDIRECT_URI` in your production environment exactly matches the one in Google Cloud Console Credentials.
- [ ] **Test Users added**: If OAuth consent screen is "In Testing", make sure all testers' Gmail addresses are listed under **Test Users**.
- [ ] **CORS & CSRF**: ThreatLens automatically includes your `OAUTH_REDIRECT_URI` in its allowed origins. If hosting frontend on a different domain, add it to `ALLOWED_ORIGINS` in `.env`.
- [ ] **Database Persistence**: If using Docker or a VPS, verify the SQLite volume mount (`sqlite_data:/app/backend` or a mounted disk) is active so user history and threat audits persist across redeploys.
