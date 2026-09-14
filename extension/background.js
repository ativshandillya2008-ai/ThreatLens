/**
 * ThreatLens Email Threat Shield — Background Service Worker (Manifest V3)
 * Manages configuration, backend communication, CSRF tokens, and threat caching.
 */

const DEFAULT_CONFIG = {
  apiUrl: "http://127.0.0.1:8088",
  fallbackUrl: "http://127.0.0.1:8088",
  activeUrl: "http://127.0.0.1:8088",
  pollIntervalMinutes: 2,
  interstitialEnabled: true,
  autoScan: true
};

// Initialize configuration on install
chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.local.get(Object.keys(DEFAULT_CONFIG));
  const toSet = {};
  for (const [key, value] of Object.entries(DEFAULT_CONFIG)) {
    if (existing[key] === undefined) {
      toSet[key] = value;
    }
  }
  if (Object.keys(toSet).length > 0) {
    await chrome.storage.local.set(toSet);
  }
  console.log("[ThreatLens] Service Worker initialized with config:", toSet);
});

// Helper: Get active API Base URL
async function getApiBaseUrl() {
  const data = await chrome.storage.local.get(["activeUrl", "apiUrl", "fallbackUrl"]);
  return data.activeUrl || data.apiUrl || DEFAULT_CONFIG.apiUrl;
}

// In-memory cache for CSRF token & threats
let cachedCsrfToken = null;

async function fetchCsrfToken(baseUrl) {
  if (cachedCsrfToken) return cachedCsrfToken;
  try {
    const res = await fetch(`${baseUrl}/api/csrf-token`, { credentials: "include" });
    if (res.ok) {
      const data = await res.json();
      cachedCsrfToken = data.csrf_token;
      return cachedCsrfToken;
    }
  } catch (err) {
    console.warn("[ThreatLens] Failed to fetch CSRF token:", err);
  }
  return null;
}

// Message Dispatcher
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const { type, payload } = request;

  if (type === "GET_CONFIG") {
    chrome.storage.local.get(null).then(sendResponse);
    return true;
  }

  if (type === "SET_CONFIG") {
    chrome.storage.local.set(payload).then(() => {
      cachedCsrfToken = null; // Invalidate CSRF on URL change
      sendResponse({ status: "ok" });
    });
    return true;
  }

  if (type === "FETCH_THREATS") {
    (async () => {
      try {
        const baseUrl = await getApiBaseUrl();
        const res = await fetch(`${baseUrl}/api/threats/?page=1&page_size=100`, {
          credentials: "include"
        });
        if (!res.ok) {
          // Attempt fallback URL if main tunnel is down
          const config = await chrome.storage.local.get(["fallbackUrl"]);
          if (config.fallbackUrl && config.fallbackUrl !== baseUrl) {
            console.log("[ThreatLens] Retrying threats fetch via fallback:", config.fallbackUrl);
            const fallbackRes = await fetch(`${config.fallbackUrl}/api/threats/?page=1&page_size=100`, {
              credentials: "include"
            });
            if (fallbackRes.ok) {
              const data = await fallbackRes.json();
              await chrome.storage.local.set({ activeUrl: config.fallbackUrl });
              sendResponse({ success: true, threats: data.threats || [] });
              return;
            }
          }
          throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        }
        const data = await res.json();
        sendResponse({ success: true, threats: data.threats || [] });
      } catch (err) {
        console.error("[ThreatLens] Error fetching threats:", err);
        sendResponse({ success: false, error: err.message, threats: [] });
      }
    })();
    return true;
  }

  if (type === "FETCH_THREAT_DETAIL") {
    (async () => {
      try {
        const baseUrl = await getApiBaseUrl();
        const res = await fetch(`${baseUrl}/api/threats/${payload.id}`, { credentials: "include" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        sendResponse({ success: true, threat: data });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }

  if (type === "SUBMIT_OVERRIDE") {
    (async () => {
      try {
        const baseUrl = await getApiBaseUrl();
        const csrfToken = await fetchCsrfToken(baseUrl);
        const headers = { "Content-Type": "application/json" };
        if (csrfToken) headers["X-CSRF-Token"] = csrfToken;

        const res = await fetch(`${baseUrl}/api/threats/${payload.id}/override`, {
          method: "POST",
          credentials: "include",
          headers,
          body: JSON.stringify({
            action: payload.action || "release",
            reason: payload.reason || "User unblocked via Chrome Extension"
          })
        });

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || `HTTP ${res.status}`);
        }

        const data = await res.json();
        sendResponse({ success: true, result: data });
      } catch (err) {
        console.error("[ThreatLens] Override submission failed:", err);
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }

  if (type === "UPDATE_BADGE_COUNT") {
    const highCount = payload.highCount || 0;
    if (highCount > 0) {
      chrome.action.setBadgeText({ text: String(highCount) });
      chrome.action.setBadgeBackgroundColor({ color: "#dc2626" });
    } else {
      chrome.action.setBadgeText({ text: "" });
    }
    sendResponse({ status: "ok" });
    return true;
  }
});
