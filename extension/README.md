# ThreatLens Email Threat Shield — Chrome Extension (Manifest V3)

A Google Chrome Extension that integrates the **ThreatLens Email Threat Detection, Geolocation, and Forensic Intelligence** engine directly into native Gmail (`mail.google.com`).

---

## Features

1. **Native Gmail Severity Badges**:
   - Injects visual indicators into Gmail's inbox rows using isolated **Shadow DOM** (prevents Gmail styling conflicts).
   - **`[✓ Safe (XX%)]`**: Dark green pill for authenticated, benign emails.
   - **`[⚠️ Suspicious (XX%)]`**: Amber warning pill for anomalous emails.
   - **`[🛑 HIGH THREAT (XX%)]`**: Pulsing red alert pill for phishing, malware lures, or spoofed emails.

2. **High-Threat Interstitial Guard**:
   - Captures user click events on High-threat emails **before** the message view or raw body HTML renders.
   - Overlays a full-screen frosted glass modal displaying:
     - Aggregated threat score percentage gauge.
     - Origin geolocation and ESP mismatch alerts.
     - SPF / DKIM / DMARC authentication failure counts.
     - Specific AI-detected phishing triggers and social engineering phrases.
     - Blacklisted / malicious URLs detected by Google Safe Browsing.
   - Two user options:
     - **"Keep in Quarantine & Close"**: Closes modal and leaves email safe in Spam.
     - **"I Understand the Risk — View Email"**: Prompts for an optional reason, logs the override to the immutable backend audit log, and safely unblocks the email view for the session.

3. **Multi-Origin Connector**:
   - Works seamlessly with both local backend (`http://127.0.0.1:8088`) and public HTTPS Cloudflare tunnel (`https://your-tunnel.trycloudflare.com`).
   - Switchable via extension popup.

---

## Installation Guide

1. Open Google Chrome and navigate to:
   ```text
   chrome://extensions/
   ```
2. Enable **Developer mode** in the top right corner.
3. Click **Load unpacked** in the top left.
4. Select the `extension` folder inside this project directory:
   ```text
   /Users/ativshandilly/Desktop/AI Powered Email Threat Detection, Geolocation and Forensic Intelligence/extension
   ```
5. Pin the **ThreatLens Email Threat Shield** icon to your Chrome toolbar.
6. Open or refresh [Gmail](https://mail.google.com).

---

## Extension Architecture

```
Chrome Browser (mail.google.com)
  ├── content.js (Injected into Gmail DOM)
  │    ├── MutationObserver (Debounced at 250ms for smooth Gmail scrolling)
  │    ├── Shadow DOM Badge Injector (Zero CSS leakage into Gmail tables)
  │    └── Capture-Phase Click Interceptor (Halt Gmail navigation on High Threats)
  │
  ├── background.js (Manifest V3 Service Worker)
  │    ├── Threat Store Cache & Polling
  │    ├── CSRF Token Management (via /api/csrf-token)
  │    └── Audit Override Dispatcher (POST /api/threats/{id}/override)
  │
  └── popup.html / popup.js (Extension Toolbar Controls)
       ├── Real-time Connection Status Indicator
       ├── Threat Statistics Counter
       └── Active API URL Switcher
```

---

## Security & Privacy Compliance

- **No Remote Code**: Built 100% compliant with Manifest V3 policies.
- **Shadow DOM Encapsulation**: Neither Gmail styles nor third-party scripts can tamper with or inspect the injected security alerts.
- **Sanitized DOM**: All dynamic values (senders, subjects, URLs, reasons) are inserted via safe DOM APIs (`textContent`, `setAttribute`), eliminating DOM-XSS risks.
