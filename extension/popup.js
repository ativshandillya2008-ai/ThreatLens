/**
 * ThreatLens Email Threat Shield — Extension Popup Controller
 */

document.addEventListener("DOMContentLoaded", async () => {
  const apiUrlInput = document.getElementById("api-url");
  const btnSave = document.getElementById("btn-save");
  const btnSync = document.getElementById("btn-sync");
  const btnDashboard = document.getElementById("btn-dashboard");
  const statusBadge = document.getElementById("status-badge");
  const statusDot = document.getElementById("status-dot");
  const statusText = document.getElementById("status-text");
  const statHigh = document.getElementById("stat-high");
  const statMed = document.getElementById("stat-med");
  const statLow = document.getElementById("stat-low");

  // Load current configuration
  chrome.runtime.sendMessage({ type: "GET_CONFIG" }, (config) => {
    if (config) {
      const activeUrl = config.activeUrl || config.apiUrl || "http://127.0.0.1:8088";
      apiUrlInput.value = activeUrl;
      btnDashboard.href = `${activeUrl}/audit`;
      checkConnection(activeUrl);
    }
  });

  // Check connection status
  async function checkConnection(url) {
    try {
      const res = await fetch(`${url}/api/csrf-token`, { credentials: "include" });
      if (res.ok) {
        statusDot.classList.remove("offline");
        statusBadge.style.color = "#10b981";
        statusBadge.style.borderColor = "rgba(16, 185, 129, 0.3)";
        statusText.textContent = "Connected";
      } else {
        throw new Error(`HTTP ${res.status}`);
      }
    } catch {
      statusDot.classList.add("offline");
      statusBadge.style.color = "#ef4444";
      statusBadge.style.borderColor = "rgba(239, 68, 68, 0.3)";
      statusText.textContent = "Offline";
    }

    // Refresh threat counts
    loadThreatCounts();
  }

  function loadThreatCounts() {
    chrome.runtime.sendMessage({ type: "FETCH_THREATS" }, (res) => {
      if (res && res.success && Array.isArray(res.threats)) {
        const high = res.threats.filter(t => t.severity === "HIGH").length;
        const med = res.threats.filter(t => t.severity === "MEDIUM").length;
        const low = res.threats.filter(t => t.severity === "LOW").length;

        statHigh.textContent = high;
        statMed.textContent = med;
        statLow.textContent = low;
      }
    });
  }

  // Save new API URL
  btnSave.addEventListener("click", () => {
    const newUrl = apiUrlInput.value.trim().replace(/\/$/, "");
    if (!newUrl) return;

    btnSave.textContent = "Connecting...";
    btnSave.disabled = true;

    chrome.runtime.sendMessage({
      type: "SET_CONFIG",
      payload: { activeUrl: newUrl, apiUrl: newUrl }
    }, () => {
      btnSave.textContent = "Saved ✓";
      setTimeout(() => {
        btnSave.textContent = "Save & Reconnect";
        btnSave.disabled = false;
      }, 1000);

      btnDashboard.href = `${newUrl}/audit`;
      checkConnection(newUrl);
    });
  });

  // Force sync
  btnSync.addEventListener("click", () => {
    btnSync.textContent = "Syncing...";
    btnSync.disabled = true;

    chrome.runtime.sendMessage({ type: "FETCH_THREATS" }, () => {
      loadThreatCounts();
      btnSync.textContent = "Synced ✓";
      setTimeout(() => {
        btnSync.textContent = "↻ Force Threat Sync";
        btnSync.disabled = false;
      }, 1000);
    });
  });
});
