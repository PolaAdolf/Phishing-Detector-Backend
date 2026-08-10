document.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(window.location.search);
  const blockedUrl = params.get('url') || 'Unknown URL';
  const reason = params.get('reason') || 'Flagged by Security Engine';

  const targetUrlEl = document.getElementById('target-url');
  const reasonDetailsEl = document.getElementById('reason-details');
  const closeBtn = document.getElementById('close-btn');
  const proceedBtn = document.getElementById('proceed-btn');

  if (targetUrlEl) targetUrlEl.textContent = blockedUrl;
  if (reasonDetailsEl) reasonDetailsEl.textContent = reason;

  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      // Use chrome.tabs API if available to close tab, fallback to window.close
      if (typeof chrome !== 'undefined' && chrome.tabs) {
        chrome.tabs.getCurrent(tab => {
          if (tab && tab.id) {
            chrome.tabs.remove(tab.id);
          } else {
            window.close();
          }
        });
      } else {
        window.close();
      }
    });
  }

  if (proceedBtn) {
    proceedBtn.addEventListener('click', () => {
      if (blockedUrl && blockedUrl !== 'Unknown URL') {
        const confirmed = confirm('⚠️ Warning: Proceeding to a flagged phishing site can compromise your banking credentials and personal security. Are you sure you want to proceed?');
        if (confirmed) {
          window.location.href = blockedUrl;
        }
      }
    });
  }
});
