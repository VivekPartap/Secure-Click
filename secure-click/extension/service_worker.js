// extension/service_worker.js
console.log("Secure-Click service worker loaded (updated)");

/**
 * Configuration
 */
const API_ENDPOINT = "http://localhost:8000/predict";
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const FETCH_TIMEOUT_MS = 10_000; // 10s
const SETTINGS_KEY = "secureClickSettings";
const TELEMETRY_KEY = "secureClickTelemetry";

/**
 * Helpers
 */
function safeKeyForUrl(url) {
  try {
    // encode but remove % for shorter keys
    return encodeURIComponent(url).replace(/%/g, "");
  } catch (e) {
    try {
      return btoa(url || "");
    } catch (err) {
      return String(url).replace(/[^a-z0-9]/gi, "_");
    }
  }
}

function normalizeUrlForCache(url) {
  if (!url) return url;
  try {
    // Remove trailing slash and lower-case host part for stable keys
    const u = new URL(url);
    u.hash = ""; // ignore hash for cache decisions
    // keep pathname case as-is but remove final trailing slash
    let path = u.pathname.replace(/\/$/, "");
    u.pathname = path;
    // normalize host to lower
    u.hostname = u.hostname.toLowerCase();
    return u.toString();
  } catch (e) {
    // fallback simple normalization
    return url.replace(/\/$/, "");
  }
}

async function fetchWithTimeout(resource, options = {}) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const resp = await fetch(resource, { signal: controller.signal, ...options });
    return resp;
  } finally {
    clearTimeout(id);
  }
}

/**
 * Load user settings from chrome.storage.sync.
 */
function getSettings() {
  return new Promise((resolve) => {
    const defaults = {
      useSafeBrowsing: true,
      useVirusTotal: true,
      aggressiveness: "balanced", // "strict" | "balanced" | "relaxed"
    };
    try {
      chrome.storage.sync.get([SETTINGS_KEY], (res) => {
        if (chrome.runtime.lastError) {
          console.warn("[Secure-Click] settings load error:", chrome.runtime.lastError);
          return resolve(defaults);
        }
        const cfg = res && res[SETTINGS_KEY] ? res[SETTINGS_KEY] : defaults;
        resolve({ ...defaults, ...cfg });
      });
    } catch (e) {
      console.error("[Secure-Click] getSettings error:", e);
      resolve(defaults);
    }
  });
}

/**
 * Record telemetry for blocks / warnings in local storage.
 */
function recordTelemetry(kind) {
  try {
    chrome.storage.local.get([TELEMETRY_KEY], (res) => {
      const current = res && res[TELEMETRY_KEY] ? res[TELEMETRY_KEY] : {};
      const updated = { blocked: current.blocked || 0, warned: current.warned || 0 };
      if (kind === "blocked") updated.blocked += 1;
      if (kind === "warned") updated.warned += 1;
      const payload = {}; payload[TELEMETRY_KEY] = updated;
      chrome.storage.local.set(payload);
    });
  } catch (e) {
    // ignore telemetry errors
  }
}

/**
 * Call backend /predict with run_safe_browsing true (if backend supports it).
 * Returns parsed JSON object on success or null on failure.
 */
async function callPredict(url) {
  if (!url) return null;
  try {
    const settings = await getSettings();
    const payload = {
      url: url,
      run_safe_browsing: !!settings.useSafeBrowsing,
      run_virustotal: !!settings.useVirusTotal,
    };
    const resp = await fetchWithTimeout(API_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!resp) {
      console.error("[Secure-Click] No response from backend");
      return null;
    }

    // Try to parse body regardless of status (some APIs return error JSON)
    let data = null;
    try {
      data = await resp.json();
    } catch (e) {
      const txt = await resp.text().catch(() => "");
      console.error("[Secure-Click] Response parse error, text:", txt.slice(0, 400));
      return null;
    }

    if (!resp.ok) {
      console.error(`[Secure-Click] Predict failed (${resp.status}):`, data);
      return null;
    }

    // Validate expected fields (score + label preferred)
    if (typeof data.score === "undefined" && typeof data.ml_score === "undefined" && typeof data.ml_score_ensemble === "undefined") {
      console.warn("[Secure-Click] Prediction response missing score fields (will still return data):", data);
    }
    if (typeof data.label === "undefined") {
      // try to infer from score if present
      if (typeof data.score === "number") {
        data.label = data.score > 0.5 ? 1 : 0;
      } else {
        console.warn("[Secure-Click] Prediction response missing label; defaulting to 0 (safe)");
        data.label = 0;
      }
    }

    return data;
  } catch (err) {
    if (err.name === "AbortError") {
      console.error("[Secure-Click] Predict request timed out");
    } else {
      console.error("[Secure-Click] Predict request error:", err);
      // Helpful hint if backend unreachable
      if (err.message && (err.message.includes("Failed to fetch") || err.message.includes("NetworkError"))) {
        console.error("Backend may not be running. Start with: uvicorn backend.app:app --reload --port 8000");
      }
    }
    return null;
  }
}

/**
 * Cache helpers - store timestamped entries so TTL works across worker restarts
 */
async function getCachedPrediction(url) {
  return new Promise((resolve) => {
    try {
      const normalized = normalizeUrlForCache(url);
      const key = "last_prediction_" + safeKeyForUrl(normalized);
      chrome.storage.local.get([key], (res) => {
        if (chrome.runtime.lastError) {
          console.warn("[Secure-Click] chrome.storage.get error:", chrome.runtime.lastError);
          return resolve(null);
        }
        const entry = res && res[key];
        if (!entry) return resolve(null);
        // entry: { data: {...}, ts: 123456789 }
        const now = Date.now();
        if (entry.ts && now - entry.ts < CACHE_TTL_MS) {
          return resolve(entry.data);
        } else {
          // expired - remove and return null
          chrome.storage.local.remove([key], () => {
            if (chrome.runtime.lastError) {
              console.warn("[Secure-Click] Error removing expired cache:", chrome.runtime.lastError);
            }
            return resolve(null);
          });
        }
      });
    } catch (e) {
      console.error("[Secure-Click] getCachedPrediction error:", e);
      resolve(null);
    }
  });
}

async function setCachedPrediction(url, data) {
  return new Promise((resolve) => {
    try {
      const normalized = normalizeUrlForCache(url);
      const key = "last_prediction_" + safeKeyForUrl(normalized);
      const entry = { data: data, ts: Date.now() };
      const payload = {}; payload[key] = entry;
      chrome.storage.local.set(payload, () => {
        if (chrome.runtime.lastError) {
          console.warn("[Secure-Click] chrome.storage.set error:", chrome.runtime.lastError);
        }
        resolve(true);
      });
    } catch (e) {
      console.error("[Secure-Click] setCachedPrediction error:", e);
      resolve(false);
    }
  });
}

/**
 * Update extension badge and create/clear notification for suspicious sites
 */
function updateBadge(tabId, data) {
  try {
    const notificationId = `secure-click-tab-${tabId}`;
    // Determine display domain
    let domain = "this site";
    try {
      const u = new URL(data.url);
      domain = u.hostname;
      if (domain.length > 40) domain = domain.slice(0, 37) + "...";
    } catch (e) {
      domain = (data.url && data.url.length > 40) ? data.url.slice(0, 37) + "..." : (data.url || "this site");
    }

    console.log(`[Secure-Click] updateBadge tab=${tabId} domain=${domain} score=${data.score} label=${data.label}`);

    if (data.label === 1 || (typeof data.score === "number" && data.score >= 0.7)) {
      chrome.action.setBadgeText({ text: "!", tabId });
      chrome.action.setBadgeBackgroundColor({ color: [220, 20, 20, 255] });
      // Clear previous and create new notification
      chrome.notifications.clear(notificationId, () => {
        const msg = `${domain} may be malicious (score ${(data.score || 0).toFixed(2)}). Click extension to view details.`;
        chrome.notifications.create(notificationId, {
          type: "basic",
          iconUrl: "icons/icon48.png",
          title: "Secure-Click Warning",
          message: msg,
          priority: 2
        }, (createdId) => {
          if (chrome.runtime.lastError) {
            console.warn("[Secure-Click] Notification create error:", chrome.runtime.lastError);
          } else {
            console.log(`[Secure-Click] Notification created: ${createdId}`);
          }
        });
      });
    } else {
      // Safe site: clear badge & notification
      chrome.action.setBadgeText({ text: "", tabId });
      chrome.notifications.clear(notificationId, (wasCleared) => {
        if (chrome.runtime.lastError) {
          // ignore
        } else if (wasCleared) {
          console.log(`[Secure-Click] cleared notification for ${domain}`);
        }
      });
    }
  } catch (e) {
    console.error("[Secure-Click] updateBadge error:", e);
  }
}

/**
 * Build query string for block/warning page with expanded params
 */
function buildBlockPageUrl(pageName, data) {
  // data may contain many fields; we encode the main useful ones
  const params = new URLSearchParams();
  params.set("url", data.url || "");
  if (typeof data.score !== "undefined") params.set("score", String(data.score));
  if (typeof data.ml_score_ensemble !== "undefined") params.set("ml_score_ensemble", String(data.ml_score_ensemble));
  // heuristics
  if (typeof data.heuristics_score !== "undefined") params.set("heuristics_score", String(data.heuristics_score));
  if (typeof data.reason !== "undefined") params.set("reason", String(data.reason));
  // external
  if (typeof data.google_safe !== "undefined") params.set("google_safe", data.google_safe ? "1" : "0");
  if (typeof data.virustotal_flag !== "undefined") params.set("virustotal_flag", data.virustotal_flag ? "1" : "0");
  if (typeof data.virustotal_positives !== "undefined") params.set("virustotal_positives", String(data.virustotal_positives || 0));
  if (typeof data.virustotal_total !== "undefined") params.set("virustotal_total", String(data.virustotal_total || 0));
  // additional ML breakdown hints (bagging/ada/gb) - try to set common keys if present
  if (typeof data.ml_score_bag !== "undefined") params.set("ml_score_bag", String(data.ml_score_bag));
  if (typeof data.ml_score_ada !== "undefined") params.set("ml_score_ada", String(data.ml_score_ada));
  if (typeof data.ml_score_gb !== "undefined") params.set("ml_score_gb", String(data.ml_score_gb));
  return chrome.runtime.getURL(`${pageName}.html?${params.toString()}`);
}

/**
 * Main listeners
 */

// When a tab finishes loading, get or fetch prediction and update badge
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  try {
    if (changeInfo.status === "complete" && tab && tab.url && (tab.url.startsWith("http://") || tab.url.startsWith("https://"))) {
      (async () => {
        const normalized = normalizeUrlForCache(tab.url);
        const cacheKey = "last_prediction_" + safeKeyForUrl(normalized);

        // Try cache first
        let data = await getCachedPrediction(normalized);
        if (data) {
          data.url = normalized;
          console.log(`[Secure-Click] Using cached prediction for ${normalized}: score=${data.score} label=${data.label}`);
        } else {
          console.log(`[Secure-Click] Fetching prediction for ${normalized}`);
          data = await callPredict(normalized);
          if (data) {
            data.url = normalized;
            await setCachedPrediction(normalized, data);
            console.log(`[Secure-Click] Cached prediction for ${normalized}`);
          }
        }

        if (data) {
          data.url = normalized;
          updateBadge(tabId, data);
          // keep last scan per tab for popup view
          const tabKey = "last_scan_tab_" + tabId;
          const obj = {}; obj[tabKey] = data;
          chrome.storage.local.set(obj, () => {
            if (chrome.runtime.lastError) {
              console.warn("[Secure-Click] storing last_scan_tab error:", chrome.runtime.lastError);
            }
          });
        }
      })();
    }
  } catch (e) {
    console.error("[Secure-Click] onUpdated handler error:", e);
  }
});

// Intercept navigations and block/redirect high risk pages
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  // Only operate on top-level frames
  if (details.frameId !== 0) return;

  (async () => {
    const url = details.url;
    if (!url || typeof url !== "string") return;

    // Ignore internal / extension / localhost
    if (url.startsWith("chrome://") || url.startsWith("chrome-extension://") ||
        url.startsWith("http://localhost") || url.startsWith("https://localhost")) {
      return;
    }

    const normalized = normalizeUrlForCache(url);
    const overrideKey = "override_" + safeKeyForUrl(normalized);

    // Check override
    chrome.storage.local.get([overrideKey], async (res) => {
      if (chrome.runtime.lastError) {
        console.warn("[Secure-Click] override check error:", chrome.runtime.lastError);
      }
      if (res && res[overrideKey]) {
        console.log(`[Secure-Click] User override exists for ${normalized} - permitting navigation`);
        return;
      }

      // Try cache
      let data = await getCachedPrediction(normalized);
      if (!data) {
        data = await callPredict(normalized);
        if (data) {
          data.url = normalized;
          await setCachedPrediction(normalized, data);
        }
      } else {
        data.url = normalized;
      }

      if (!data) return;

      // Save into blockedUrls map for quick lookup (optional)
      // blockedUrls.set(normalized, { score: data.score, label: data.label, reason: data.reason, ts: Date.now() });

      // Decide action: block if label=1 and score high; show warning for moderate scores
      const score = typeof data.score === "number" ? data.score : (data.ml_score_ensemble || data.ml_score || 0);
      const label = typeof data.label === "number" ? data.label : (score > 0.5 ? 1 : 0);
      const settings = await getSettings();
      let blockThreshold = 0.7;
      let warnThreshold = 0.5;
      if (settings.aggressiveness === "strict") {
        blockThreshold = 0.6;
        warnThreshold = 0.4;
      } else if (settings.aggressiveness === "relaxed") {
        blockThreshold = 0.85;
        warnThreshold = 0.65;
      }

      try {
        if (label === 1 && score >= blockThreshold) {
          // Hard block -> show block.html
          const blockUrl = buildBlockPageUrl("block", data);
          console.log(`[Secure-Click] Blocking navigation to ${normalized}, redirecting to ${blockUrl}`);
          chrome.tabs.update(details.tabId, { url: blockUrl });
          recordTelemetry("blocked");
        } else if (label === 1 && score >= warnThreshold) {
          // Suspicious -> show warning page (less strict)
          const warnUrl = buildBlockPageUrl("warning", data);
          console.log(`[Secure-Click] Showing warning for ${normalized}, redirecting to ${warnUrl}`);
          chrome.tabs.update(details.tabId, { url: warnUrl });
          recordTelemetry("warned");
        } else {
          // safe -> allow
        }
      } catch (e) {
        console.error("[Secure-Click] Error while redirecting:", e);
      }
    });
  })();
}, { url: [{ schemes: ["http", "https"] }] });

// Handle SPA navigation (history API changes)
chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId !== 0) return;

  (async () => {
    const url = details.url;
    if (!url) return;

    const normalized = normalizeUrlForCache(url);
    const overrideKey = "override_" + safeKeyForUrl(normalized);

    chrome.storage.local.get([overrideKey], async (res) => {
      if (res && res[overrideKey]) return;

      let data = await getCachedPrediction(normalized);
      if (!data) {
        data = await callPredict(normalized);
        if (data) {
          data.url = normalized;
          await setCachedPrediction(normalized, data);
        }
      } else {
        data.url = normalized;
      }

      if (!data) return;

      const score = typeof data.score === "number" ? data.score : (data.ml_score_ensemble || data.ml_score || 0);
      const label = typeof data.label === "number" ? data.label : (score > 0.5 ? 1 : 0);

      if (label === 1 && score >= 0.7) {
        // Attempt to notify content script; if none, fallback to redirect to warning page
        try {
          chrome.tabs.sendMessage(details.tabId, {
            type: "SECURECLICK_WARNING",
            url: normalized,
            score,
            reason: data.reason || "Suspicious site"
          }, (response) => {
            if (chrome.runtime.lastError) {
              // likely no content script in this page - fallback to redirect (warning)
              const warnUrl = buildBlockPageUrl("warning", data);
              chrome.tabs.update(details.tabId, { url: warnUrl });
            } else {
              // content script handled it
            }
          });
        } catch (e) {
          const warnUrl = buildBlockPageUrl("warning", data);
          chrome.tabs.update(details.tabId, { url: warnUrl });
        }
      }
    });
  })();
}, { url: [{ schemes: ["http", "https"] }] });

// Cleanup per-tab stored scan when tab removed
chrome.tabs.onRemoved.addListener((tabId) => {
  const tabKey = "last_scan_tab_" + tabId;
  chrome.storage.local.remove([tabKey], () => {
    if (chrome.runtime.lastError) {
      // ignore
    } else {
      // console.log(`[Secure-Click] removed last_scan_tab_${tabId}`);
    }
  });
});
