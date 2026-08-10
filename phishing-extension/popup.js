const BACKEND_URL = 'http://127.0.0.1:8000/scan';

document.addEventListener('DOMContentLoaded', () => {
  const urlDisplay = document.getElementById('url-display');
  const badge = document.getElementById('status-badge');
  const score = document.getElementById('risk-score');
  const reason = document.getElementById('reason-text');
  const scanBtn = document.getElementById('scan-btn');

  function analyzeUrl(url) {
    urlDisplay.textContent = url;
    badge.className = 'badge LOADING';
    badge.textContent = 'ANALYZING';
    score.textContent = '...';
    reason.textContent = 'Scanning URL with backend multi-layer engine...';

    fetch(BACKEND_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url })
    })
      .then(res => res.json())
      .then(data => {
        const isPhishing = data.status === 'DANGER' || data.is_phishing;
        badge.className = `badge ${isPhishing ? 'DANGER' : 'SAFE'}`;
        badge.textContent = isPhishing ? 'MALICIOUS' : 'SAFE';
        score.textContent = `${data.risk_score}% Risk`;
        reason.textContent = data.reason || (isPhishing ? 'High risk pattern detected' : 'Clean URL verified');
      })
      .catch(err => {
        badge.className = 'badge DANGER';
        badge.textContent = 'OFFLINE';
        score.textContent = 'ERR';
        reason.textContent = 'Cannot connect to FastAPI Backend at http://127.0.0.1:8000';
      });
  }

  // Get active tab URL
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    if (tabs && tabs[0] && tabs[0].url) {
      analyzeUrl(tabs[0].url);
    } else {
      urlDisplay.textContent = 'No active tab URL found.';
    }
  });

  scanBtn.addEventListener('click', () => {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (tabs && tabs[0] && tabs[0].url) {
        analyzeUrl(tabs[0].url);
      }
    });
  });
});