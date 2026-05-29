// background.js - Service Worker for Fraud Shield Guard extension
// Listens for messages from content script, performs API calls to the Fraud Shield AI backend,
// logs threats, and shows Chrome notifications.

const BACKEND_ORIGIN = 'http://localhost:3000'; // backend URL

chrome.runtime.onInstalled.addListener(() => {
  // Open the Fraud Shield dashboard (served by the local backend)
  chrome.tabs.create({ url: `${BACKEND_ORIGIN}/` });
});

chrome.runtime.onStartup.addListener(() => {
  chrome.tabs.create({ url: `${BACKEND_ORIGIN}/` });
});

// Helper to send POST request to backend
async function post(endpoint, data) {
  const resp = await fetch(`${BACKEND_ORIGIN}${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return resp.json();
}

// Listen for messages from content script
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg.type === 'url_scan') {
      // Scan the current page URL
      const { url } = msg;
      const result = await post('/api/scan-url', { url });
    // Always generate a notification (even if not suspicious) so the user sees the analysis
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon48.svg',
      title: `🔎 URL Scan – Score: ${result.analysis.score}`,
      message: `${result.analysis.isSuspicious ? '⚠️ Suspicious' : '✅ Clean'} – ${result.analysis.indicators.map(i => i.name).join(', ') || 'No indicators'}\n\nAI Brief:\n${result.aiBrief || 'No brief available.'}`
    });
    // Log blocked URLs only when suspicious
    if (result.success && result.analysis.isSuspicious) {
      await post('/api/threats/log', {
        type: 'url',
        input: url,
        score: result.analysis.score,
        indicators: result.analysis.indicators,
        aiBrief: result.aiBrief,
        status: 'blocked'
      });
    }
        // Notify user immediately
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon48.svg',
          title: '⚠️ Fraud Shield Guard – Suspicious Site',
          message: `Score: ${result.analysis.score}\n${result.analysis.indicators.map(i=>i.name).join(', ')}`
        });
        // Log to backend as a blocked URL
        await post('/api/threats/log', {
          type: 'url',
          input: url,
          score: result.analysis.score,
          indicators: result.analysis.indicators,
          aiBrief: result.aiBrief,
          status: 'blocked'
        });
      }
    } else if (msg.type === 'tx_scan') {
      // Transaction form submission intercepted
      const tx = msg.txData; // {upiId, amount, name, note, originUrl}
      const result = await post('/api/analyze-transaction', tx);
      // Send the analysis back to content script for UI handling
      sendResponse({ analysis: result.analysis, aiBrief: result.aiBrief });
      // Log outcome later (content script will call log endpoint after user decision)
    }
  })();
  // Keep channel open for async response
  return true;
});

// Optional: react to navigation events to scan URLs automatically
chrome.webNavigation.onCompleted.addListener(details => {
  chrome.scripting.executeScript({
    target: { tabId: details.tabId },
    func: () => {
      // Send current URL to background for scanning
      chrome.runtime.sendMessage({ type: 'url_scan', url: location.href });
    }
  });
});
