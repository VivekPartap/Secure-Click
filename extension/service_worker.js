// extension/service_worker.js
console.log("Secure-Click service worker loaded");

async function callPredict(url) {
  try {
    const resp = await fetch("http://localhost:8000/predict", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({url: url, run_safe_browsing: true})
    });
    if (!resp.ok) {
      const errorText = await resp.text();
      console.error("Predict failed", resp.status, errorText);
      return null;
    }
    const data = await resp.json();
    // Ensure data has all required fields
    if (!data || typeof data.score === 'undefined' || typeof data.label === 'undefined') {
      console.error("Invalid response data:", data);
      return null;
    }
    return data;
  } catch (err) {
    console.error("Predict request error", err);
    // Check if backend is reachable
    if (err.message?.includes('Failed to fetch') || err.message?.includes('NetworkError')) {
      console.error("Backend server may not be running. Please start it with: uvicorn backend.app:app --reload --port 8000");
    }
    return null;
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && (tab.url.startsWith("http://") || tab.url.startsWith("https://"))) {
    // Normalize URL for consistent caching (remove trailing slash, convert to lowercase for comparison)
    const normalizedUrl = tab.url.replace(/\/$/, '');
    const cacheKey = "last_prediction_" + encodeURIComponent(normalizedUrl);
    
    chrome.storage.local.get([cacheKey], async (res) => {
      let data = null;
      
      if (res && res[cacheKey]) {
        // Use cached result
        data = res[cacheKey];
        console.log(`[Secure-Click] Using cached result for ${normalizedUrl}: score=${data.score}, label=${data.label}`);
      } else {
        // Fetch new prediction
        console.log(`[Secure-Click] Fetching prediction for ${normalizedUrl}`);
        data = await callPredict(normalizedUrl);
        if (data) {
          // Always use the normalized tab URL
          data.url = normalizedUrl;
          // Cache for 5 minutes
          const obj = {};
          obj[cacheKey] = data;
          chrome.storage.local.set(obj);
          setTimeout(() => { 
            chrome.storage.local.remove(cacheKey);
            console.log(`[Secure-Click] Cache expired for ${normalizedUrl}`);
          }, 5 * 60 * 1000);
          console.log(`[Secure-Click] Cached result for ${normalizedUrl}: score=${data.score}, label=${data.label}`);
        }
      }
      
      if (data) {
        // Ensure URL is always the current tab URL
        data.url = normalizedUrl;
        // Update badge and notification
        updateBadge(tabId, data);
        // Store for popup
        chrome.storage.local.set({["last_scan_tab_" + tabId]: data});
      }
    });
  }
});

function updateBadge(tabId, data) {
  try {
    // Use a consistent notification ID per tab so it gets replaced
    const notificationId = `secure-click-tab-${tabId}`;
    
    // Extract domain from URL for notification (always use data.url which should be the current tab URL)
    let domain = "this site";
    try {
      const urlObj = new URL(data.url);
      domain = urlObj.hostname;
      // Truncate long domains
      if (domain.length > 40) {
        domain = domain.substring(0, 37) + "...";
      }
    } catch (e) {
      // If URL parsing fails, use a shortened version of the URL
      if (data.url && data.url.length > 40) {
        domain = data.url.substring(0, 37) + "...";
      } else {
        domain = data.url || "this site";
      }
    }
    
    console.log(`[Secure-Click] updateBadge for tab ${tabId}, URL: ${data.url}, domain: ${domain}, score: ${data.score}, label: ${data.label}`);
    
    if (data.label === 1) {
      chrome.action.setBadgeText({text: "!", tabId: tabId});
      chrome.action.setBadgeBackgroundColor({color: [220, 20, 20, 255]});
      
      // Clear any existing notification first, then create new one
      chrome.notifications.clear(notificationId, () => {
        // Create new notification with current URL and score
        chrome.notifications.create(notificationId, {
          type: "basic",
          iconUrl: "icons/icon48.png",
          title: "Secure-Click Warning",
          message: `${domain} seems to be suspicious (score ${data.score.toFixed(2)}). Click extension to see details.`
        }, (createdId) => {
          if (chrome.runtime.lastError) {
            console.error("[Secure-Click] Notification creation error:", chrome.runtime.lastError);
          } else {
            console.log(`[Secure-Click] Notification created for ${domain} with score ${data.score.toFixed(2)}`);
          }
        });
      });
    } else {
      chrome.action.setBadgeText({text: "", tabId: tabId});
      // Clear notification for safe sites
      chrome.notifications.clear(notificationId, (wasCleared) => {
        // Ignore errors if notification doesn't exist
        if (wasCleared) {
          console.log(`[Secure-Click] Cleared notification for safe site: ${domain}`);
        }
      });
    }
  } catch (e) {
    console.error("[Secure-Click] Badge update error:", e);
  }
}

// cleanup when tab removed
chrome.tabs.onRemoved.addListener((tabId, removeInfo) => {
  chrome.storage.local.remove("last_scan_tab_" + tabId);
});
