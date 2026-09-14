/**
 * ThreatLens Email Threat Shield — Content Script (Manifest V3)
 * Injected into https://mail.google.com/*
 *
 * Features:
 * 1. Debounced DOM observer for Gmail inbox/spam/search message rows.
 * 2. Visual threat badges injected into rows using isolated Shadow DOM.
 * 3. High-Threat Click Interceptor (Capture phase) triggering an interstitial modal.
 * 4. User override flow communicating with the backend via background service worker.
 */

(() => {
  "use strict";

  // Prevent double injection
  if (window.__OMNI_AI_SHIELD_LOADED__) return;
  window.__OMNI_AI_SHIELD_LOADED__ = true;

  console.log("[ThreatLens] Email Threat Shield loaded into Gmail.");

  // Local threat database cache: { message_id, subject_norm, sender_norm }
  let threatStore = [];
  const sessionOverrides = new Set(); // threat IDs user unblocked during this browser session
  let isScanning = false;
  let debounceTimer = null;

  // ── 1. Fetch Threats from Background ───────────────────────────────────────
  function refreshThreatData() {
    chrome.runtime.sendMessage({ type: "FETCH_THREATS" }, (response) => {
      if (response && response.success && Array.isArray(response.threats)) {
        threatStore = response.threats;
        console.log(`[ThreatLens] Synchronized ${threatStore.length} threat records.`);
        
        // Update badge count in extension icon
        const highCount = threatStore.filter(t => t.severity === "HIGH").length;
        chrome.runtime.sendMessage({ type: "UPDATE_BADGE_COUNT", payload: { highCount } });

        // Trigger scan of visible rows
        scheduleScan();
      }
    });
  }

  // Refresh immediately, then every 30 seconds
  refreshThreatData();
  setInterval(refreshThreatData, 30000);

  // ── 2. String Normalization for Resilient Matching ─────────────────────────
  function normalizeText(text) {
    if (!text) return "";
    return text
      .toLowerCase()
      .replace(/^(re|fwd|fw):\s*/gi, "")
      .replace(/[\s\-_]+/g, " ")
      .trim();
  }

  function extractSenderEmail(senderStr) {
    if (!senderStr) return "";
    const match = senderStr.match(/<([^>]+)>/) || senderStr.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    return match ? match[1].toLowerCase().trim() : senderStr.toLowerCase().trim();
  }

  // ── 3. Find Matching Threat for a Gmail Row ────────────────────────────────
  function matchThreat(row) {
    if (!threatStore || threatStore.length === 0) return null;

    // Check message / thread ID attributes
    const threadId = row.getAttribute("data-legacy-thread-id") ||
                     row.getAttribute("data-thread-id") ||
                     row.getAttribute("id") || "";

    // Extract sender
    const senderElem = row.querySelector("span[email]") ||
                       row.querySelector(".bda") ||
                       row.querySelector(".yX .bqe") ||
                       row.querySelector(".yP");
    const rowSenderEmail = senderElem ? (senderElem.getAttribute("email") || senderElem.textContent) : "";
    const normRowSender = extractSenderEmail(rowSenderEmail);

    // Extract subject
    const subjectElem = row.querySelector(".bog") ||
                        row.querySelector(".y6 span") ||
                        row.querySelector("span[data-thread-id]");
    const rowSubject = subjectElem ? subjectElem.textContent : "";
    const normRowSubject = normalizeText(rowSubject);

    for (const threat of threatStore) {
      // Direct message ID match
      if (thread.message_id && threadId && thread.message_id.includes(threadId)) {
        return threat;
      }

      // Robust sender + subject match
      const threatSenderEmail = extractSenderEmail(threat.sender);
      const threatNormSubject = normalizeText(threat.subject);

      if (normRowSubject && threatNormSubject && normRowSubject === threatNormSubject) {
        if (!normRowSender || !threatSenderEmail || normRowSender.includes(threatSenderEmail) || threatSenderEmail.includes(normRowSender)) {
          return threat;
        }
      }
    }

    return null;
  }

  // ── 4. Shadow DOM Badge Creator ────────────────────────────────────────────
  function createBadgeElement(threat) {
    const host = document.createElement("span");
    host.className = "omni-badge-host";

    const shadow = host.attachShadow({ mode: "open" });

    let bg, border, color, icon, label;
    const scorePct = Math.round((threat.final_score || 0) * 100);

    if (threat.severity === "HIGH") {
      bg = "linear-gradient(135deg, #7f1d1d 0%, #991b1b 100%)";
      border = "#dc2626";
      color = "#fecaca";
      icon = "🛑";
      label = `HIGH THREAT (${scorePct}%)`;
    } else if (threat.severity === "MEDIUM") {
      bg = "linear-gradient(135deg, #78350f 0%, #92400e 100%)";
      border = "#f59e0b";
      color = "#fef3c7";
      icon = "⚠️";
      label = `SUSPICIOUS (${scorePct}%)`;
    } else {
      bg = "linear-gradient(135deg, #064e3b 0%, #065f46 100%)";
      border = "#10b981";
      color = "#d1fae5";
      icon = "✓";
      label = `SAFE (${scorePct}%)`;
    }

    const style = document.createElement("style");
    style.textContent = `
      .badge {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 2px 8px;
        border-radius: 9999px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.03em;
        text-transform: uppercase;
        background: ${bg};
        border: 1px solid ${border};
        color: ${color};
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
        cursor: pointer;
        user-select: none;
        transition: transform 0.15s ease, box-shadow 0.15s ease;
      }
      .badge:hover {
        transform: scale(1.04);
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.4);
      }
      .badge-icon {
        font-size: 11px;
      }
    `;

    const badge = document.createElement("span");
    badge.className = "badge";
    badge.title = `ThreatLens Forensic Assessment: ${threat.severity} (${scorePct}% threat score)`;
    badge.innerHTML = `<span class="badge-icon">${icon}</span><span>${label}</span>`;

    shadow.appendChild(style);
    shadow.appendChild(badge);

    return host;
  }

  // ── 5. High-Threat Interstitial Guard ───────────────────────────────────────
  function showThreatInterstitial(threat, onProceed) {
    // Remove any existing modal
    const existing = document.querySelector(".omni-interstitial-host");
    if (existing) existing.remove();

    const host = document.createElement("div");
    host.className = "omni-interstitial-host";

    const shadow = host.attachShadow({ mode: "open" });

    const scorePct = Math.round((threat.final_score || 0) * 100);

    // Parse JSON evidence fields safely
    let reasoningList = [];
    try {
      reasoningList = typeof threat.llm_reasoning === "string" ? JSON.parse(threat.llm_reasoning) : (threat.llm_reasoning || []);
    } catch {
      reasoningList = [];
    }

    let unsafeUrls = {};
    try {
      unsafeUrls = typeof threat.unsafe_urls === "string" ? JSON.parse(threat.unsafe_urls) : (threat.unsafe_urls || {});
    } catch {
      unsafeUrls = {};
    }

    const authFailures = [threat.spf, threat.dkim, threat.dmarc].filter(v => v === "fail").length;

    const style = document.createElement("style");
    style.textContent = `
      .backdrop {
        position: fixed;
        inset: 0;
        background: rgba(3, 7, 18, 0.88);
        backdrop-filter: blur(8px);
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 20px;
        box-sizing: border-box;
      }
      .modal {
        background: #0f172a;
        border: 1px solid #7f1d1d;
        border-radius: 16px;
        box-shadow: 0 25px 50px -12px rgba(220, 38, 38, 0.35);
        max-width: 640px;
        width: 100%;
        color: #f1f5f9;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        overflow: hidden;
        animation: modalIn 0.2s ease-out;
      }
      @keyframes modalIn {
        from { opacity: 0; transform: scale(0.96); }
        to { opacity: 1; transform: scale(1); }
      }
      .header {
        background: linear-gradient(135deg, #7f1d1d 0%, #450a0a 100%);
        padding: 20px 24px;
        border-bottom: 1px solid #991b1b;
        display: flex;
        align-items: center;
        gap: 16px;
      }
      .header-icon {
        font-size: 32px;
      }
      .header-title {
        margin: 0;
        font-size: 20px;
        font-weight: 700;
        color: #fef2f2;
      }
      .header-subtitle {
        margin: 4px 0 0;
        font-size: 13px;
        color: #fca5a5;
      }
      .body {
        padding: 24px;
        display: flex;
        flex-direction: column;
        gap: 18px;
        max-height: 65vh;
        overflow-y: auto;
      }
      .metric-card {
        background: #090d16;
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 14px 18px;
      }
      .score-bar-container {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 8px;
        font-size: 13px;
        font-weight: 600;
      }
      .score-bar {
        height: 8px;
        background: #1e293b;
        border-radius: 9999px;
        overflow: hidden;
      }
      .score-bar-fill {
        height: 100%;
        background: linear-gradient(90deg, #f59e0b 0%, #dc2626 100%);
        width: ${scorePct}%;
        border-radius: 9999px;
      }
      .grid-3 {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 10px;
        font-size: 12px;
      }
      .grid-item {
        background: #1e293b;
        padding: 8px 12px;
        border-radius: 6px;
      }
      .grid-item-label {
        color: #94a3b8;
        font-size: 11px;
        margin-bottom: 2px;
      }
      .grid-item-value {
        font-weight: 600;
        color: #f8fafc;
        text-transform: capitalize;
      }
      .bullets {
        margin: 6px 0 0;
        padding-left: 18px;
        font-size: 13px;
        color: #cbd5e1;
        line-height: 1.5;
      }
      .url-box {
        background: rgba(220, 38, 38, 0.1);
        border: 1px solid rgba(220, 38, 38, 0.3);
        border-radius: 8px;
        padding: 10px 14px;
        font-family: monospace;
        font-size: 12px;
        color: #fca5a5;
        word-break: break-all;
      }
      .input-reason {
        width: 100%;
        background: #090d16;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 10px 14px;
        font-size: 13px;
        color: #f1f5f9;
        box-sizing: border-box;
      }
      .input-reason:focus {
        outline: none;
        border-color: #3b82f6;
      }
      .footer {
        padding: 16px 24px;
        background: #090d16;
        border-top: 1px solid #1e293b;
        display: flex;
        justify-content: flex-end;
        gap: 12px;
      }
      .btn {
        padding: 10px 18px;
        border-radius: 8px;
        font-size: 13px;
        font-weight: 600;
        cursor: pointer;
        transition: background 0.15s ease;
        border: none;
      }
      .btn-cancel {
        background: #1e293b;
        color: #cbd5e1;
      }
      .btn-cancel:hover {
        background: #334155;
      }
      .btn-proceed {
        background: #dc2626;
        color: #fff;
      }
      .btn-proceed:hover {
        background: #b91c1c;
      }
    `;

    const backdrop = document.createElement("div");
    backdrop.className = "backdrop";

    const modal = document.createElement("div");
    modal.className = "modal";

    modal.innerHTML = `
      <div class="header">
        <span class="header-icon">🛑</span>
        <div>
          <h2 class="header-title">High-Threat Email Blocked by ThreatLens</h2>
          <p class="header-subtitle">Threat Score: ${scorePct}% • Potential Phishing / Social Engineering Attack</p>
        </div>
      </div>
      <div class="body">
        <div class="metric-card">
          <div class="score-bar-container">
            <span>Aggregated Threat Level</span>
            <span style="color: #f87171">${scorePct}%</span>
          </div>
          <div class="score-bar">
            <div class="score-bar-fill"></div>
          </div>
        </div>

        <div class="grid-3">
          <div class="grid-item">
            <div class="grid-item-label">Attack Vector</div>
            <div class="grid-item-value">${threat.llm_threat_type ? threat.llm_threat_type.replace(/_/g, ' ') : 'Suspicious'}</div>
          </div>
          <div class="grid-item">
            <div class="grid-item-label">Origin Location</div>
            <div class="grid-item-value">${threat.geo_country || 'Unknown'}${threat.geo_mismatch ? ' (Mismatch!)' : ''}</div>
          </div>
          <div class="grid-item">
            <div class="grid-item-label">Auth Failures</div>
            <div class="grid-item-value" style="color: ${authFailures > 0 ? '#f87171' : '#4ade80'}">${authFailures} of 3 Failed</div>
          </div>
        </div>

        ${reasoningList.length > 0 ? `
          <div>
            <span style="font-size: 13px; font-weight: 600; color: #94a3b8;">Why ThreatLens Flagged This:</span>
            <ul class="bullets">
              ${reasoningList.map(item => `<li>${item}</li>`).join('')}
            </ul>
          </div>
        ` : ''}

        ${Object.keys(unsafeUrls).length > 0 ? `
          <div>
            <span style="font-size: 13px; font-weight: 600; color: #f87171;">Malicious URLs Detected:</span>
            <div style="margin-top: 6px; display: flex; flex-direction: column; gap: 4px;">
              ${Object.entries(unsafeUrls).map(([url, type]) => `
                <div class="url-box">⚠️ [${type}] ${url}</div>
              `).join('')}
            </div>
          </div>
        ` : ''}

        <div>
          <label style="display: block; font-size: 12px; color: #94a3b8; margin-bottom: 6px;">
            Optional: Reason for opening (Logged in Forensic Audit Trail)
          </label>
          <input type="text" class="input-reason" placeholder="e.g. Expected invoice from known vendor..." />
        </div>
      </div>
      <div class="footer">
        <button class="btn btn-cancel" id="btn-keep">Keep Quarantined & Close</button>
        <button class="btn btn-proceed" id="btn-open">I Understand the Risk — View Email</button>
      </div>
    `;

    shadow.appendChild(style);
    shadow.appendChild(backdrop);
    backdrop.appendChild(modal);
    document.body.appendChild(host);

    // Event listeners
    const btnKeep = shadow.getElementById("btn-keep");
    const btnOpen = shadow.getElementById("btn-open");
    const reasonInput = shadow.querySelector(".input-reason");

    btnKeep.addEventListener("click", () => {
      host.remove();
    });

    btnOpen.addEventListener("click", () => {
      btnOpen.textContent = "Logging Override...";
      btnOpen.disabled = true;

      const reason = reasonInput.value.trim() || "User overrode High-Threat Interstitial Guard in Gmail";

      chrome.runtime.sendMessage({
        type: "SUBMIT_OVERRIDE",
        payload: { id: threat.id, action: "release", reason }
      }, (res) => {
        host.remove();
        if (typeof onProceed === "function") {
          onProceed();
        }
      });
    });

    // Trap Escape key
    const onKey = (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
      }
    };
    window.addEventListener("keydown", onKey, true);
  }

  // ── 6. Scan and Inject Badges into Gmail Rows ──────────────────────────────
  function scanGmailRows() {
    if (isScanning) return;
    isScanning = true;

    try {
      // Common Gmail row selectors (Standard view, Split view, Preview pane)
      const rows = document.querySelectorAll("tr.zA, div.zA, [role='row']");

      rows.forEach(row => {
        // Skip if already processed with a badge
        if (row.dataset.omniScanned === "true") return;

        const threat = matchThreat(row);
        if (!threat) return;

        // Mark as scanned
        row.dataset.omniScanned = "true";
        row.dataset.omniThreatId = threat.id;
        row.dataset.omniSeverity = threat.severity;

        // Add subtle class for row border
        if (threat.severity === "HIGH") {
          row.classList.add("omni-threat-high");
        } else if (threat.severity === "MEDIUM") {
          row.classList.add("omni-threat-medium");
        } else if (threat.severity === "LOW") {
          row.classList.add("omni-threat-low");
        }

        // Inject Shadow DOM Badge
        const badgeElem = createBadgeElement(threat);

        // Find the best injection anchor (subject snippet element)
        const targetContainer = row.querySelector(".bog") ||
                                row.querySelector(".y6") ||
                                row.querySelector(".xY") ||
                                row.querySelector("[role='gridcell']:nth-child(5)") ||
                                row.children[3] ||
                                row;

        if (targetContainer) {
          if (targetContainer.firstChild) {
            targetContainer.insertBefore(badgeElem, targetContainer.firstChild);
          } else {
            targetContainer.appendChild(badgeElem);
          }
        }

        // Intercept click on HIGH-threat rows in CAPTURE phase
        if (threat.severity === "HIGH") {
          row.addEventListener("click", (e) => {
            // If already unblocked for this session, allow navigation
            if (sessionOverrides.has(threat.id)) {
              return;
            }

            // Halt Gmail's default row opening
            e.preventDefault();
            e.stopPropagation();
            e.stopImmediatePropagation();

            showThreatInterstitial(threat, () => {
              sessionOverrides.add(threat.id);
              // Re-trigger click so user opens the message
              row.click();
            });
          }, true); // Important: true = capture phase
        }
      });
    } finally {
      isScanning = false;
    }
  }

  // ── 7. Debounced Observer for Gmail Dynamic Loading ────────────────────────
  function scheduleScan() {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      scanGmailRows();
    }, 250);
  }

  const observer = new MutationObserver((mutations) => {
    let hasRelevantChanges = false;
    for (const m of mutations) {
      if (m.addedNodes && m.addedNodes.length > 0) {
        hasRelevantChanges = true;
        break;
      }
    }
    if (hasRelevantChanges) {
      scheduleScan();
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });

  // Initial scan
  scheduleScan();
})();
