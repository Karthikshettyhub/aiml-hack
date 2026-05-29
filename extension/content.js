// content.js – runs in the context of every visited page
// Detects suspicious payment forms, urgency text, and sends data to background for analysis.

// Utility: simple heuristic checks on page content (client‑side fast checks)
function hasUrgencyWording(text) {
  const patterns = [/\bexpires? in\b/i, /\bclaim (now|immediately)\b/i, /\breward waiting\b/i, /\blimited time\b/i];
  return patterns.some(p => p.test(text));
}

function isPaymentForm(form) {
  // Heuristic: contains fields typical for payments
  const hasUPI = !!form.querySelector('input[name*="upi"], input[id*="upi"]');
  const hasAmount = !!form.querySelector('input[name*="amount"], input[id*="amount"]');
  const hasSubmit = !!form.querySelector('button[type="submit"], input[type="submit"]');
  return (hasUPI && hasAmount) || hasSubmit;
}

function extractFormData(form) {
  const name = (form.querySelector('input[name*="name"], input[id*="name"]')?.value?.trim() || '');
  const upiId = (form.querySelector('input[name*="upi"], input[id*="upi"]')?.value?.trim() || '');
  const amount = parseFloat((form.querySelector('input[name*="amount"], input[id*="amount"]')?.value) || 0);
  const note = (form.querySelector('input[name*="note"], input[id*="note"]')?.value?.trim() || '');
  return { name, upiId, amount, note, originUrl: location.href };
}

// Intercept form submissions
document.addEventListener('submit', async event => {
  const form = event.target;
  if (!isPaymentForm(form)) return; // not a payment form

  const formData = extractFormData(form);
  if (!formData.upiId || !formData.amount) return; // insufficient data

  // Block default submission until analysis finishes
  event.preventDefault();

  // Send data to background for analysis
  chrome.runtime.sendMessage({ type: 'tx_scan', txData: formData }, response => {
    const { analysis, aiBrief } = response;
    // Decide what to do based on risk score
    if (analysis && analysis.isSuspicious) {
      // Show interceptor overlay (reuse same UI as in app.js if available)
      showInterceptorOverlay(formData, analysis, aiBrief);
    } else {
      // Safe – submit the form normally (for demo we just alert)
      alert('✅ Transaction appears safe (demo). No real payment will be processed.');
    }
  });
});

// Simple urgency text detection – runs on page load
if (hasUrgencyWording(document.body.innerText)) {
  // Notify background that page contains urgency cues
  chrome.runtime.sendMessage({ type: 'url_scan', url: location.href });
}

// UI overlay for interception – injected into page
function showInterceptorOverlay(txData, analysis, aiBrief) {
  // Create overlay element
  const overlay = document.createElement('div');
  overlay.id = 'fraud-shield-interceptor';
  overlay.style = `
    position:fixed;top:0;left:0;width:100vw;height:100vh;z-index:2147483647;
    background:rgba(0,0,0,0.85);backdrop-filter:blur(6px);
    display:flex;flex-direction:column;justify-content:center;align-items:center;color:#fff;
    font-family:Arial,Helvetica,sans-serif;`
    ;
  overlay.innerHTML = `
    <div style="max-width:380px;background:rgba(0,0,0,0.6);padding:24px;border-radius:12px;box-shadow:0 0 20px #ff00c8;">
      <h2 style="margin-top:0;color:#ff4081;">⚠️ Fraud Shield Guard</h2>
      <p><strong>Risk Score:</strong> ${analysis.score} (${analysis.riskLevel || 'Suspicious'})</p>
      <p><strong>Indicators:</strong></p>
      <ul style="font-size:0.9rem;">
        ${analysis.indicators.map(i => `<li>${i.name}</li>`).join('')}
      </ul>
      <p style="margin-top:12px;font-size:0.85rem;">${aiBrief || ''}</p>
      <div style="margin-top:16px;text-align:center;">
        <button id="fs-abort" style="background:#e53935;color:#fff;padding:8px 16px;border:none;border-radius:6px;margin-right:8px;cursor:pointer;">Abort & Secure</button>
        <button id="fs-bypass" style="background:#ffb300;color:#000;padding:8px 16px;border:none;border-radius:6px;cursor:pointer;">Bypass (Demo)</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  // Button handlers
  document.getElementById('fs-abort').addEventListener('click', () => {
    // Log blocked transaction
    chrome.runtime.sendMessage({
      type: 'log_tx',
      payload: { ...txData, score: analysis.score, indicators: analysis.indicators, aiBrief, status: 'blocked' }
    });
    overlay.remove();
  });
  document.getElementById('fs-bypass').addEventListener('click', () => {
    // For demo we just log as bypassed and then allow form submission
    chrome.runtime.sendMessage({
      type: 'log_tx',
      payload: { ...txData, score: analysis.score, indicators: analysis.indicators, aiBrief, status: 'bypassed' }
    });
    overlay.remove();
    // Re‑submit the form programmatically (still no real payment)
    alert('⚠️ Bypassed – no real money will be transferred (demo mode).');
  });
}

// Listen for logging messages from background (optional)
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'log_tx') {
    // Forward to backend using fetch (background could also do it, but we keep simple here)
    fetch(`${BACKEND_ORIGIN}/api/threats/log`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'transaction',
        input: msg.payload,
        score: msg.payload.score,
        indicators: msg.payload.indicators,
        aiBrief: msg.payload.aiBrief,
        status: msg.payload.status
      })
    });
  }
});
