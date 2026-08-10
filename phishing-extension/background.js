// Background Service Worker for Real-Time Phishing Link Scanner
const BACKEND_URL = 'http://127.0.0.1:8000/scan';

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
    // Avoid scanning internal warning or extension pages
    if (tab.url.includes(chrome.runtime.id)) {
      return;
    }

    fetch(BACKEND_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: tab.url })
    })
      .then(response => response.json())
      .then(data => {
        if (data.status === 'DANGER' || data.is_phishing) {
          // Set Red Badge
          chrome.action.setBadgeText({ text: '!', tabId: tabId });
          chrome.action.setBadgeBackgroundColor({ color: '#DC3545', tabId: tabId });

          // Create Alert Notification
          chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icon.png',
            title: '⚠️ Malicious Link Intercepted!',
            message: `Warning: ${data.url} flagged as phishing (${data.risk_score}% risk).\n${data.reason}`,
            priority: 2
          });

          // Redirect to Warning Block Page
          const warningUrl = chrome.runtime.getURL(`warning.html?url=${encodeURIComponent(tab.url)}&reason=${encodeURIComponent(data.reason)}&score=${data.risk_score}`);
          chrome.tabs.update(tabId, { url: warningUrl });
        } else {
          // Set Green Badge for Safe Sites
          chrome.action.setBadgeText({ text: '✓', tabId: tabId });
          chrome.action.setBadgeBackgroundColor({ color: '#28A745', tabId: tabId });
        }
      })
      .catch(err => {
        console.warn('Backend offline or error connecting:', err);
        chrome.action.setBadgeText({ text: '?', tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#6C757D', tabId: tabId });
      });
  }
});