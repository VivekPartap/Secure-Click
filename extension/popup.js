// extension/popup.js
document.addEventListener('DOMContentLoaded', async () => {
  const statusEl = document.getElementById('status');
  const detailsEl = document.getElementById('details');
  const controlsEl = document.getElementById('controls');
  const urlEl = document.getElementById('url');
  const verdictEl = document.getElementById('verdict');
  const scoreEl = document.getElementById('score');
  const reasonEl = document.getElementById('reason');

  statusEl.textContent = "Getting active tab...";
  try {
    const tabs = await chrome.tabs.query({active: true, currentWindow: true});
    if (!tabs || tabs.length === 0) {
      statusEl.textContent = "No active tab found.";
      return;
    }
    const tab = tabs[0];
    
    // Check if URL is valid
    if (!tab.url || (!tab.url.startsWith("http://") && !tab.url.startsWith("https://"))) {
      statusEl.textContent = "This page cannot be scanned (not an HTTP/HTTPS page).";
      return;
    }
    
    const tabKey = "last_scan_tab_" + tab.id;
    chrome.storage.local.get([tabKey], (res) => {
      const data = res[tabKey];
      if (!data) {
        statusEl.textContent = "No scan result cached for this tab. Wait a few seconds for the extension to analyze.";
        // Try to trigger a scan if not cached
        setTimeout(() => {
          chrome.storage.local.get([tabKey], (retryRes) => {
            if (retryRes[tabKey]) {
              location.reload();
            }
          });
        }, 3000);
        return;
      }
      statusEl.style.display = "none";
      detailsEl.style.display = "block";
      controlsEl.style.display = "block";
      urlEl.textContent = data.url;
      scoreEl.textContent = typeof data.score === 'number' ? data.score.toFixed(3) : 'N/A';
      reasonEl.textContent = data.reason || "No reason provided";
      if (data.label === 1) {
        verdictEl.textContent = "Seems to be Suspicious";
        verdictEl.className = "mal";
      } else {
        verdictEl.textContent = "Seems to be Safe";
        verdictEl.className = "safe";
      }
    });
  } catch (e) {
    statusEl.textContent = "Popup error: " + e.toString();
    console.error("Popup error details:", e);
  }

  // Set up dashboard button click handler
  const dashboardBtn = document.getElementById('openDashboard');
  if (dashboardBtn) {
    dashboardBtn.addEventListener('click', () => {
      // open local dashboard if you host it at :3000 or open backend history
      chrome.tabs.create({url: "http://localhost:3000"});
    });
  }
});
