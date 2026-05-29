// Fraud Shield AI - Premium Interactivity Frontend Script
// Seamless UI transitions, custom glowing ChartJS configurations, and transaction flows

// Application State
let activeView = 'dashboard';
let telemetryData = { threats: [], stats: {} };
let lineChart = null;
let pieChart = null;
let currentScamType = 'reward';
let currentTransactionIntercept = null;
let repeatedAttempts = 0;

// API Base URL
const API_BASE = '';

// DOM Elements
const views = {
  dashboard: document.getElementById('dashboard'),
  scanner: document.getElementById('scanner'),
  emulator: document.getElementById('emulator')
};

const navItems = document.querySelectorAll('.nav-item');
const viewTitle = document.getElementById('view-title');
const viewSubtitle = document.getElementById('view-subtitle');
const resetBtn = document.getElementById('reset-telemetry-btn');
const toast = document.getElementById('system-toast');
const toastText = document.getElementById('toast-text');

// Initialize on Load
document.addEventListener('DOMContentLoaded', () => {
  setupNavigation();
  fetchTelemetry();
  setupURLScanner();
  setupPaymentEmulator();
  setupInterceptorHUD();
  
  resetBtn.addEventListener('click', resetTelemetry);
  
  // Refresh stats periodically
  setInterval(fetchTelemetry, 15000);
});

// Toast Notifications
function showToast(text, duration = 4000) {
  toastText.textContent = text;
  toast.classList.add('show-toast');
  setTimeout(() => {
    toast.classList.remove('show-toast');
  }, duration);
}

// Sidebar Navigation Router
function setupNavigation() {
  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const targetView = item.getAttribute('data-view');
      
      // Update sidebar state
      navItems.forEach(nav => nav.classList.remove('active'));
      item.classList.add('active');
      
      // Hide old view, show new view
      Object.keys(views).forEach(v => {
        views[v].classList.remove('active-view');
      });
      views[targetView].classList.add('active-view');
      
      // Update headings
      activeView = targetView;
      updateHeaderTitles(targetView);
    });
  });
}

function updateHeaderTitles(view) {
  if (view === 'dashboard') {
    viewTitle.textContent = 'Cyber Dashboard';
    viewSubtitle.textContent = 'Real-time threat feeds and statistical telemetry heuristics';
  } else if (view === 'scanner') {
    viewTitle.textContent = 'URL Scan Hub';
    viewSubtitle.textContent = 'Inspect network domain assets against threat markers';
  } else if (view === 'emulator') {
    viewTitle.textContent = 'Fintech Simulator';
    viewSubtitle.textContent = 'Simulate mobile UPI billing pages inside high-risk networks';
  }
}

// ========================================================
// TELEMETRY & METRIC DATABASE LOGIC
// ========================================================
async function fetchTelemetry() {
  try {
    const res = await fetch(`${API_BASE}/api/threats`);
    const data = await res.json();
    if (data.success) {
      telemetryData = data;
      updateDashboardUI();
    }
  } catch (err) {
    console.error('Telemetry fetch error:', err);
    showToast('Telemetry server offline. Using Local Cache.');
  }
}

function updateDashboardUI() {
  const stats = telemetryData.stats;
  if (!stats) return;

  // 1. Sync statistics cards
  document.getElementById('stat-scanned').textContent = stats.totalScanned;
  document.getElementById('stat-blocked').textContent = stats.totalBlocked;
  document.getElementById('stat-bypassed').textContent = stats.totalBypassed;
  document.getElementById('stat-risk').textContent = `${stats.avgRiskScore}/100`;

  // 2. Render Incident List feed
  const feedContainer = document.getElementById('threats-feed-container');
  feedContainer.innerHTML = '';
  
  if (telemetryData.threats.length === 0) {
    feedContainer.innerHTML = `<div style="text-align:center; padding: 30px; color: var(--text-muted);">No incident telemetry logged yet.</div>`;
  } else {
    telemetryData.threats.forEach(threat => {
      const row = document.createElement('div');
      row.className = `feed-item type-${threat.type}`;
      
      const timeStr = new Date(threat.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      const dateStr = new Date(threat.timestamp).toLocaleDateString([], { month: 'short', day: 'numeric' });
      
      let avatarHtml = '';
      let titleText = '';
      
      if (threat.type === 'url') {
        avatarHtml = `<i class="fa-solid fa-globe"></i>`;
        titleText = threat.input;
      } else {
        avatarHtml = `<i class="fa-solid fa-mobile-button"></i>`;
        titleText = `P2P Transfer to ${threat.input.merchantName || threat.input.upiId}`;
      }

      let severityClass = 'medium';
      if (threat.score >= 80) severityClass = 'critical';
      else if (threat.score >= 50) severityClass = 'high';

      let statusHtml = '';
      if (threat.status === 'blocked' || threat.status === 'aborted') {
        statusHtml = `<span class="badge-status blocked">SECURED</span>`;
      } else {
        statusHtml = `<span class="badge-status bypassed">BYPASS</span>`;
      }

      row.innerHTML = `
        <div class="feed-left">
          <div class="feed-avatar">${avatarHtml}</div>
          <div class="feed-info">
            <h4 class="mono" title="${titleText}">${titleText}</h4>
            <p><i class="fa-regular fa-clock"></i> ${dateStr} at ${timeStr} • ID: ${threat.id}</p>
          </div>
        </div>
        <div class="feed-right">
          <span class="badge-score ${severityClass} mono">${threat.score} Risk</span>
          ${statusHtml}
        </div>
      `;
      feedContainer.appendChild(row);
    });
  }

  // 3. Render/Update Charts
  renderTelemetryCharts(stats);
}

// Custom futuristic ChartJS setup mimicking premium Recharts
function renderTelemetryCharts(stats) {
  const trendData = stats.dailyTrends || [];
  const dates = trendData.map(d => d.date);
  const scannedCounts = trendData.map(d => d.scanned);
  const blockedCounts = trendData.map(d => d.blocked);

  // A. Line Chart (Threat Telemetry Trends)
  if (lineChart) {
    lineChart.data.labels = dates;
    lineChart.data.datasets[0].data = scannedCounts;
    lineChart.data.datasets[1].data = blockedCounts;
    lineChart.update();
  } else {
    const ctx = document.getElementById('lineChartActivity').getContext('2d');
    
    // Create neon blue and neon magenta gradients
    const gradCyan = ctx.createLinearGradient(0, 0, 0, 300);
    gradCyan.addColorStop(0, 'rgba(0, 240, 255, 0.15)');
    gradCyan.addColorStop(1, 'rgba(0, 240, 255, 0)');

    const gradPink = ctx.createLinearGradient(0, 0, 0, 300);
    gradPink.addColorStop(0, 'rgba(255, 0, 85, 0.15)');
    gradPink.addColorStop(1, 'rgba(255, 0, 85, 0)');

    lineChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: dates,
        datasets: [
          {
            label: 'Total Scans',
            data: scannedCounts,
            borderColor: '#00f0ff',
            backgroundColor: gradCyan,
            borderWidth: 2,
            pointBackgroundColor: '#00f0ff',
            pointHoverBorderColor: '#00f0ff',
            pointRadius: 3,
            fill: true,
            tension: 0.35
          },
          {
            label: 'Threats Blocked',
            data: blockedCounts,
            borderColor: '#ff0055',
            backgroundColor: gradPink,
            borderWidth: 2,
            pointBackgroundColor: '#ff0055',
            pointHoverBorderColor: '#ff0055',
            pointRadius: 3,
            fill: true,
            tension: 0.35
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            labels: { color: '#9ca3af', font: { family: 'Outfit', size: 11 } }
          },
          tooltip: {
            backgroundColor: '#0a0b12',
            titleColor: '#fff',
            bodyColor: '#fff',
            borderColor: 'rgba(0, 240, 255, 0.15)',
            borderWidth: 1,
            titleFont: { family: 'Outfit' },
            bodyFont: { family: 'JetBrains Mono' }
          }
        },
        scales: {
          x: {
            grid: { color: 'rgba(255, 255, 255, 0.03)' },
            ticks: { color: '#6b7280', font: { family: 'Outfit' } }
          },
          y: {
            grid: { color: 'rgba(255, 255, 255, 0.03)' },
            ticks: { color: '#6b7280', font: { family: 'Outfit' }, stepSize: 1 }
          }
        }
      }
    });
  }

  // B. Pie Chart (Vector Analysis)
  // Calculate specific vectors breakout based on current log indicators
  let tldCount = 0;
  let impersonationCount = 0;
  let urgencyCount = 0;
  let highAmountCount = 0;
  let burnerUpiCount = 0;

  telemetryData.threats.forEach(t => {
    const list = t.indicators || [];
    list.forEach(i => {
      const name = i.name.toLowerCase();
      if (name.includes('tld') || name.includes('tld')) tldCount++;
      if (name.includes('impersonation') || name.includes('typosquatting')) impersonationCount++;
      if (name.includes('urgency') || name.includes('psychological')) urgencyCount++;
      if (name.includes('amount') || name.includes('checkout')) highAmountCount++;
      if (name.includes('upi') || name.includes('numeric')) burnerUpiCount++;
    });
  });

  const vectorData = [
    Math.max(tldCount, 1),
    Math.max(impersonationCount, 2),
    Math.max(urgencyCount, 3),
    Math.max(burnerUpiCount, 1),
    Math.max(highAmountCount, 1)
  ];

  if (pieChart) {
    pieChart.data.datasets[0].data = vectorData;
    pieChart.update();
  } else {
    const ctx = document.getElementById('pieChartVector').getContext('2d');
    pieChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Risk TLDs', 'Impersonation', 'Urgency Texts', 'Burner UPIs', 'High Escrow'],
        datasets: [{
          data: vectorData,
          backgroundColor: [
            'rgba(0, 240, 255, 0.8)',
            'rgba(255, 0, 85, 0.8)',
            'rgba(255, 159, 0, 0.8)',
            'rgba(168, 85, 247, 0.8)',
            'rgba(57, 255, 20, 0.8)'
          ],
          borderColor: '#06070b',
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '65%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#9ca3af', boxWidth: 10, padding: 12, font: { family: 'Outfit', size: 10 } }
          },
          tooltip: {
            backgroundColor: '#0a0b12',
            borderColor: 'rgba(255, 255, 255, 0.08)',
            borderWidth: 1,
            titleFont: { family: 'Outfit' },
            bodyFont: { family: 'JetBrains Mono' }
          }
        }
      }
    });
  }
}

// Reset Telemetry Database Action
async function resetTelemetry() {
  try {
    const res = await fetch(`${API_BASE}/api/threats/reset`, { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      telemetryData.stats = data.stats;
      await fetchTelemetry();
      repeatedAttempts = 0;
      showToast('Database reset successfully.');
    }
  } catch (err) {
    console.error('Reset error:', err);
  }
}

// ========================================================
// URL SCANNER ENGINE CONTROLS
// ========================================================
function setupURLScanner() {
  const scanInput = document.getElementById('url-scan-input');
  const scanBtn = document.getElementById('run-scan-btn');
  const placeholder = document.getElementById('scanner-placeholder');
  const resultsBox = document.getElementById('scanner-results');
  
  const indicatorsList = document.getElementById('hud-indicators-container');
  const aiContent = document.getElementById('hud-ai-content');
  
  // Preset list item clicks
  const presets = document.querySelectorAll('.preset-item');
  presets.forEach(p => {
    p.addEventListener('click', () => {
      const url = p.getAttribute('data-url');
      scanInput.value = url;
      executeScan(url);
    });
  });

  scanBtn.addEventListener('click', () => {
    const url = scanInput.value.trim();
    if (url) {
      executeScan(url);
    } else {
      showToast('Please type a URL domain to inspect.');
    }
  });

  scanInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const url = scanInput.value.trim();
      if (url) executeScan(url);
    }
  });

  async function executeScan(url) {
    // Show spinner inside button
    scanBtn.disabled = true;
    scanBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Scanning`;
    
    try {
      const res = await fetch(`${API_BASE}/api/scan-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      const data = await res.json();
      
      if (data.success) {
        // Toggle view display
        placeholder.style.display = 'none';
        resultsBox.style.display = 'block';
        
        renderScanReport(data.analysis, data.aiBrief);
        fetchTelemetry(); // refresh stats as the scan was saved on the backend
      }
    } catch (err) {
      console.error('Scan URL API error:', err);
      showToast('Scanner module offline.');
    } finally {
      scanBtn.disabled = false;
      scanBtn.innerHTML = `<i class="fa-solid fa-shield-virus"></i> Inspect`;
    }
  }

  function renderScanReport(analysis, aiBrief) {
    const verdictEl = document.getElementById('hud-verdict');
    const metaEl = document.getElementById('hud-meta');
    const scoreNum = document.getElementById('hud-score-num');
    const gaugeFill = document.getElementById('hud-gauge-fill');
    const statusWrapper = document.getElementById('hud-status-wrapper');
    const titleContainer = document.getElementById('hud-title-container');

    // 1. Verdict display styling
    if (analysis.isSuspicious) {
      verdictEl.textContent = 'HIGH RISK DETECTED';
      metaEl.textContent = `Security analysis flagged malicious markers inside "${analysis.details.domain}"`;
      
      statusWrapper.className = 'analysis-hud danger';
      titleContainer.className = 'analysis-title danger';
    } else {
      verdictEl.textContent = 'SECURE DOMAIN';
      metaEl.textContent = `The domain "${analysis.details.domain}" shows standard commercial credentials.`;
      
      statusWrapper.className = 'analysis-hud safe';
      titleContainer.className = 'analysis-title safe';
    }

    // 2. Score number and circular gauge animation
    scoreNum.textContent = analysis.score;
    // Circular calculations (r=40, circumference = 251.2)
    const offset = 251.2 - (analysis.score / 100) * 251.2;
    gaugeFill.style.strokeDashoffset = offset;

    // 3. Render indicator list items
    indicatorsList.innerHTML = '';
    if (analysis.indicators.length === 0) {
      indicatorsList.innerHTML = `
        <div class="indicator-row" style="border-color: rgba(57, 255, 20, 0.15);">
          <i class="fa-solid fa-circle-check ind-icon" style="color: var(--neon-green);"></i>
          <div class="ind-content">
            <h4>No Malicious Signals Detected</h4>
            <p>This web address passed TLD audits, typosquatting calculations, SSL verification, and keyword checks.</p>
          </div>
        </div>
      `;
    } else {
      analysis.indicators.forEach(ind => {
        const item = document.createElement('div');
        item.className = `indicator-row ${ind.severity}`;
        
        let iconHtml = '';
        if (ind.severity === 'high') {
          iconHtml = `<i class="fa-solid fa-triangle-exclamation ind-icon"></i>`;
        } else {
          iconHtml = `<i class="fa-solid fa-circle-exclamation ind-icon" style="color: var(--neon-amber);"></i>`;
        }

        item.innerHTML = `
          ${iconHtml}
          <div class="ind-content">
            <h4>${ind.name}</h4>
            <p>${ind.description}</p>
          </div>
        `;
        indicatorsList.appendChild(item);
      });
    }

    // 4. Render AI explanation (parse simple markdown bold/bullet indicators)
    aiContent.innerHTML = formatMarkdownToHtml(aiBrief || 'Analyzing safety indicators...');
  }
}

// Helper to render basic Markdown headings/bold/bullets
function formatMarkdownToHtml(md) {
  if (!md) return '';
  let html = md;
  // Replace Headings ###
  html = html.replace(/^### (.*$)/gim, '<h3 style="font-size:0.95rem; color:#fff; font-weight:bold; margin: 12px 0 6px 0;">$1</h3>');
  // Replace bold **text**
  html = html.replace(/\*\*(.*?)\*\*/g, '<strong style="color:var(--neon-cyan); font-weight:600;">$1</strong>');
  // Replace bullet points
  html = html.replace(/^\- (.*$)/gim, '<li style="margin-left: 12px; margin-bottom: 4px; list-style-type: square; font-size: 0.76rem;">$1</li>');
  
  // Wrap li blocks in ul if necessary
  if (html.includes('<li>')) {
    html = html.replace(/(<li>.*<\/li>)/gms, '<ul style="margin: 8px 0; padding-left: 6px;">$1</ul>');
  }

  // Replace linebreaks
  html = html.replace(/\n/g, '<br>');
  return html;
}

// ========================================================
// UPI SCAM PAYMENTS PHONE EMULATOR
// ========================================================
function setupPaymentEmulator() {
  const simBtns = document.querySelectorAll('.sim-btn');
  const browserAddressBar = document.getElementById('browser-address-bar');
  const browserAddressText = document.getElementById('browser-address-text');
  const phoneViewport = document.getElementById('emulator-web-viewport');
  const simulatePayBtn = document.getElementById('simulate-pay-btn');

  simBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      simBtns.forEach(b => b.classList.remove('active-sim'));
      btn.classList.add('active-sim');
      
      const scamType = btn.getAttribute('data-scam');
      currentScamType = scamType;
      loadScamTemplate(scamType);
    });
  });

  function loadScamTemplate(type) {
    if (type === 'reward') {
      // Setup browser bar
      browserAddressBar.className = 'phone-address-input unsafe';
      browserAddressText.textContent = 'google-rewards-verification.ru/billing';
      
      // Update phone viewport HTML
      phoneViewport.innerHTML = `
        <div class="scam-template-reward">
          <div class="reward-top">
            <div class="reward-gift-box">
              <i class="fa-solid fa-gift"></i>
            </div>
            <h2>Congratulations Winner!</h2>
            <p class="scam-sub">You have won an immediate cashback prize from UPI Escrow desk!</p>
            
            <div class="reward-box-claim">
              <span>PRIZE VALUE</span>
              <h3>₹25,000.00</h3>
            </div>
          </div>

          <div class="reward-form">
            <div class="pay-form-group">
              <label>Claiming UPI Handle Address</label>
              <input type="text" id="phone-upi-id" value="claim-rewards99@ybl">
            </div>
            <div class="pay-form-group">
              <label>Merchant Gateway Collector</label>
              <input type="text" id="phone-merchant" value="Verification Payout Center" readonly style="opacity: 0.65;">
            </div>
            <div class="pay-form-group">
              <label>Refundable Authorization Fee</label>
              <input type="number" id="phone-amount" value="25000" readonly style="opacity: 0.65;">
            </div>

            <button class="scam-pay-btn" id="phone-pay-btn">
              <i class="fa-solid fa-bolt"></i> Claim Cashback Now
            </button>
          </div>
        </div>
      `;
    } 
    else if (type === 'billing') {
      browserAddressBar.className = 'phone-address-input unsafe';
      browserAddressText.textContent = 'paytma-wallet-alert.xyz/safety-verify';
      
      phoneViewport.innerHTML = `
        <div class="scam-template-reward" style="height: 100%;">
          <div class="reward-top">
            <div class="reward-gift-box" style="color: var(--neon-pink);">
              <i class="fa-solid fa-triangle-exclamation"></i>
            </div>
            <h2 style="color: var(--neon-pink);">Immediate Security Alert!</h2>
            <p class="scam-sub" style="color: #ff9ca8;">Your financial account faces lock warnings. Verify escrow funds immediately.</p>
            
            <div class="reward-box-claim" style="background: rgba(255, 0, 85, 0.05); border-color: rgba(255,0,85,0.3);">
              <span style="color:#ff9ca8;">VERIFICATION DEPOSIT SUM</span>
              <h3 style="color: var(--neon-pink);">₹75,000.00</h3>
            </div>
          </div>

          <div class="reward-form">
            <div class="pay-form-group">
              <label>Secure Transfer Handle</label>
              <input type="text" id="phone-upi-id" value="chase-escrow-desk@ybl">
            </div>
            <div class="pay-form-group">
              <label>Escrow Department</label>
              <input type="text" id="phone-merchant" value="Safety Administration Center" readonly style="opacity: 0.65;">
            </div>
            <div class="pay-form-group">
              <label>Verification Escrow Deposit Sum</label>
              <input type="number" id="phone-amount" value="75000" readonly style="opacity: 0.65;">
            </div>

            <button class="scam-pay-btn" id="phone-pay-btn" style="background: linear-gradient(135deg, var(--neon-pink), #bf003f); color: #fff; box-shadow: 0 4px 14px rgba(255,0,85,0.3);">
              <i class="fa-solid fa-lock-open"></i> Unlock Wallet Escrow
            </button>
          </div>
        </div>
      `;
    } 
    else if (type === 'legit') {
      browserAddressBar.className = 'phone-address-input safe';
      browserAddressText.textContent = 'https://store.steampowered.com/checkout';
      
      phoneViewport.innerHTML = `
        <div class="scam-template-reward" style="height: 100%;">
          <div class="reward-top">
            <div class="reward-gift-box" style="color: var(--neon-green);">
              <i class="fa-solid fa-gamepad"></i>
            </div>
            <h2 style="color: var(--neon-green);">Valve Steam Checkout</h2>
            <p class="scam-sub">Secure checkout gateway for selected item downloads.</p>
            
            <div class="reward-box-claim" style="background: rgba(57, 255, 20, 0.05); border-color: rgba(57,255,20,0.3);">
              <span style="color:#8dfb7d;">TOTAL CHECKOUT AMOUNT</span>
              <h3 style="color: var(--neon-green);">₹1,499.00</h3>
            </div>
          </div>

          <div class="reward-form">
            <div class="pay-form-group">
              <label>Sender UPI Address</label>
              <input type="text" id="phone-upi-id" value="purchases@ybl">
            </div>
            <div class="pay-form-group">
              <label>Corporate Recipient</label>
              <input type="text" id="phone-merchant" value="Valve Steam Corp" readonly style="opacity: 0.65;">
            </div>
            <div class="pay-form-group">
              <label>Total Checkout Sum (INR)</label>
              <input type="number" id="phone-amount" value="1499" readonly style="opacity: 0.65;">
            </div>

            <button class="scam-pay-btn" id="phone-pay-btn" style="background: linear-gradient(135deg, var(--neon-green), #20a000); color: #000; box-shadow: 0 4px 14px rgba(57,255,20,0.3);">
              <i class="fa-solid fa-circle-check"></i> Complete Secure Purchase
            </button>
          </div>
        </div>
      `;
    }

    // Rebind phone click listener inside dynamic layout
    const phoneBtn = document.getElementById('phone-pay-btn');
    phoneBtn.addEventListener('click', triggerPhonePayment);
  }

  // Bind initial click
  const phoneBtn = document.getElementById('simulate-pay-btn');
  if (phoneBtn) phoneBtn.addEventListener('click', triggerPhonePayment);

  // Core Pay trigger inside emulator
  async function triggerPhonePayment() {
    const payBtn = document.getElementById('phone-pay-btn') || document.getElementById('simulate-pay-btn');
    
    // Obtain dynamic fields
    const upiId = document.getElementById('phone-upi-id')?.value || 'claim-rewards99@ybl';
    const amount = document.getElementById('phone-amount')?.value || 25000;
    const merchantName = document.getElementById('phone-merchant')?.value || 'Verification Payout Gateway';
    const note = currentScamType === 'reward' ? 'Claim Cashback Reward Now' : currentScamType === 'billing' ? 'Emergency Escrow Lock release Fee' : 'Steam game purchase checkout';
    
    repeatedAttempts++; // Track session clicks

    // Disable button to simulate network processing latency
    payBtn.disabled = true;
    payBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> INTERCEPTING WORKFLOW...`;

    try {
      const payload = {
        upiId,
        amount,
        merchantName,
        note,
        repeatedAttempts,
        originUrl: browserAddressText.textContent
      };

      const res = await fetch(`${API_BASE}/api/analyze-transaction`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();

      // Artificial payment network delay for cyber feel
      setTimeout(() => {
        if (data.success) {
          if (data.analysis.isSuspicious) {
            // Save state for outcome decisions
            currentTransactionIntercept = {
              type: 'transaction',
              input: payload,
              score: data.analysis.score,
              indicators: data.analysis.indicators,
              aiBrief: data.aiBrief
            };
            // Trigger intercept Overlay HUD
            openInterceptorOverlay(currentTransactionIntercept);
          } else {
            // Scenario C: Successful secure checkout rendered inside simulator
            renderSecureSuccessfulLayout();
          }
        }
        
        // Restore pay button
        payBtn.disabled = false;
        payBtn.innerHTML = currentScamType === 'reward' ? 
          `<i class="fa-solid fa-bolt"></i> Claim Cashback Now` : 
          currentScamType === 'billing' ? 
          `<i class="fa-solid fa-lock-open"></i> Unlock Wallet Escrow` : 
          `<i class="fa-solid fa-circle-check"></i> Complete Secure Purchase`;
      }, 1000);

    } catch (err) {
      console.error('Analyze transaction error:', err);
      showToast('Escrow gateway analysis failed.');
      payBtn.disabled = false;
      payBtn.innerHTML = `Complete Purchase`;
    }
  }

  function renderSecureSuccessfulLayout() {
    phoneViewport.innerHTML = `
      <div style="display:flex; flex-direction:column; align-items:center; justify-content:center; height:100%; text-align:center; padding: 20px; animation: fadeIn 0.4s forwards;">
        <i class="fa-solid fa-circle-check" style="font-size: 64px; color: var(--neon-green); filter: drop-shadow(0 0 10px rgba(57, 255, 20, 0.4)); margin-bottom: 18px; animation: bounce 1.5s infinite;"></i>
        <h2 style="color: var(--neon-green); font-weight: bold; margin-bottom: 6px;">Secure Payment Complete</h2>
        <p style="font-size: 0.78rem; color: var(--text-secondary); line-height: 1.5; margin-bottom: 24px;">
          Funds have been successfully deposited. Gateway secured via active certificate pin inspection.
        </p>
        <div style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); border-radius: 8px; width: 100%; padding: 14px; text-align: left; font-family:'JetBrains Mono'; font-size: 0.68rem;">
          <div style="color: var(--text-muted); margin-bottom:4px;">REFERENCE REF-8239A</div>
          <div>STATUS: PAID</div>
          <div>MERCHANT: Valve Steam Corp</div>
          <div>SUM: ₹1,499.00</div>
        </div>
        <button class="scam-pay-btn" onclick="location.reload()" style="background: transparent; border: 1px solid rgba(255,255,255,0.15); color: #fff; box-shadow:none; font-size: 0.75rem; margin-top:20px;">
          Reload Demo
        </button>
      </div>
    `;
  }
}

// ========================================================
// REAL-TIME INTERCEPTOR HUD OVERLAY
// ========================================================
function setupInterceptorHUD() {
  const overlay = document.getElementById('threat-interceptor-overlay');
  const abortBtn = document.getElementById('intercept-abort-btn');
  const bypassBtn = document.getElementById('intercept-bypass-btn');

  abortBtn.addEventListener('click', async () => {
    if (!currentTransactionIntercept) return;
    
    // Log ABORT event in backend
    try {
      const res = await fetch(`${API_BASE}/api/threats/log`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'transaction',
          input: currentTransactionIntercept.input,
          score: currentTransactionIntercept.score,
          indicators: currentTransactionIntercept.indicators,
          aiBrief: currentTransactionIntercept.aiBrief,
          status: 'blocked'
        })
      });
      const data = await res.json();
      if (data.success) {
        showToast('🛡️ Security Shield Active: Outflow blocked. Fraud logged.');
        closeInterceptorOverlay();
        renderTransactionAbortedLayout();
        fetchTelemetry(); // refresh stats
      }
    } catch (err) {
      console.error('Abort log error:', err);
    }
  });

  bypassBtn.addEventListener('click', async () => {
    if (!currentTransactionIntercept) return;
    
    const confirmForced = confirm("CRITICAL SECURITY DANGER:\n\nProceeding will bypass Fraud Shield AI filters and authorize this payment.\nScammers may immediately drain these funds.\n\nAre you absolutely sure you want to force this payment?");
    
    if (confirmForced) {
      // Log BYPASS event in backend
      try {
        const res = await fetch(`${API_BASE}/api/threats/log`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: 'transaction',
            input: currentTransactionIntercept.input,
            score: currentTransactionIntercept.score,
            indicators: currentTransactionIntercept.indicators,
            aiBrief: currentTransactionIntercept.aiBrief,
            status: 'bypassed'
          })
        });
        const data = await res.json();
        if (data.success) {
          showToast('⚠️ Danger Warning: Telemetry logged. Security filter bypassed.');
          closeInterceptorOverlay();
          renderTransactionCompromisedLayout();
          fetchTelemetry(); // refresh stats
        }
      } catch (err) {
        console.error('Bypass log error:', err);
      }
    }
  });
}

function openInterceptorOverlay(threat) {
  const overlay = document.getElementById('threat-interceptor-overlay');
  
  // Fill text details
  document.getElementById('intercept-id').textContent = `TH-${Math.floor(1000 + Math.random() * 9000)}`;
  document.getElementById('intercept-origin').textContent = threat.input.originUrl || 'unknown-portal';
  document.getElementById('intercept-merchant').textContent = threat.input.merchantName || 'Unknown Gateway';
  document.getElementById('intercept-upi').textContent = threat.input.upiId || 'Unknown UPI';
  
  const amt = parseFloat(threat.input.amount);
  document.getElementById('intercept-amount').textContent = `₹${amt.toLocaleString()}`;
  document.getElementById('intercept-score').textContent = `${threat.score}/100`;

  // Render indicator row bubbles inside Interceptor
  const indContainer = document.getElementById('intercept-indicators-box');
  indContainer.innerHTML = '';
  threat.indicators.forEach(i => {
    const bubble = document.createElement('div');
    bubble.className = `indicator-row ${i.severity}`;
    bubble.style.padding = '8px 12px';
    bubble.style.marginBottom = '6px';
    bubble.innerHTML = `
      <i class="fa-solid fa-triangle-exclamation ind-icon" style="font-size:14px; margin-top:2px;"></i>
      <div class="ind-content">
        <h4 style="font-size:0.75rem;">${i.name}</h4>
      </div>
    `;
    indContainer.appendChild(bubble);
  });

  // Render AI Threat analysis brief
  document.getElementById('intercept-ai-report').innerHTML = formatMarkdownToHtml(threat.aiBrief);

  // Play a cool mock retro computer alert chime using simple HTML WebAudio synth!
  playAlertChime();

  // Show
  overlay.classList.add('show-overlay');
}

function closeInterceptorOverlay() {
  const overlay = document.getElementById('threat-interceptor-overlay');
  overlay.classList.remove('show-overlay');
}

// Interactive mockup layout rendering: TRANSACTION ABORTED
function renderTransactionAbortedLayout() {
  const phoneViewport = document.getElementById('emulator-web-viewport');
  phoneViewport.innerHTML = `
    <div style="display:flex; flex-direction:column; align-items:center; justify-content:center; height:100%; text-align:center; padding: 20px; animation: fadeIn 0.4s forwards;">
      <i class="fa-solid fa-shield-halved" style="font-size: 64px; color: var(--neon-green); filter: drop-shadow(0 0 10px rgba(57, 255, 20, 0.4)); margin-bottom: 18px; animation: pulse-green 2s infinite;"></i>
      <h2 style="color: var(--neon-green); font-weight: bold; margin-bottom: 6px;">Payment Terminated</h2>
      <p style="font-size: 0.78rem; color: var(--text-secondary); line-height: 1.5; margin-bottom: 24px;">
        Fraud Shield AI successfully intercepted this request. No money has left your banking wallet.
      </p>
      <div style="background: rgba(57, 255, 20, 0.02); border: 1px solid rgba(57, 255, 20, 0.15); border-radius: 8px; width: 100%; padding: 14px; text-align: left; font-family:'JetBrains Mono'; font-size: 0.68rem; color:#8dfb7d;">
        <div>SHIELD RESULT: SECURED</div>
        <div>INCIDENT: TRAP INTERCEPTED</div>
        <div>POTENTIAL DAMAGE: ₹${parseFloat(currentTransactionIntercept.input.amount).toLocaleString()}</div>
      </div>
      <button class="scam-pay-btn" onclick="location.reload()" style="background: var(--neon-green); border: none; color: #000; box-shadow:var(--neon-green-glow); font-size: 0.75rem; margin-top:20px;">
        Restart Simulation
      </button>
    </div>
  `;
}

// Interactive mockup layout rendering: SIMULATED DAMAGE SYSTEM COMPROMISE
function renderTransactionCompromisedLayout() {
  const phoneViewport = document.getElementById('emulator-web-viewport');
  const amt = parseFloat(currentTransactionIntercept.input.amount).toLocaleString();
  
  phoneViewport.innerHTML = `
    <div style="display:flex; flex-direction:column; align-items:center; justify-content:center; height:100%; text-align:center; padding: 20px; background: rgba(255, 0, 85, 0.03); border: 1px solid rgba(255, 0, 85, 0.1); animation: fadeIn 0.4s forwards;">
      <i class="fa-solid fa-skull-crossbones" style="font-size: 64px; color: var(--neon-pink); filter: drop-shadow(0 0 10px rgba(255, 0, 85, 0.4)); margin-bottom: 18px; animation: flash-red 1.5s infinite;"></i>
      <h2 style="color: var(--neon-pink); font-weight: bold; margin-bottom: 6px;">Account Drained</h2>
      <p style="font-size: 0.78rem; color: #ff9ca8; line-height: 1.5; margin-bottom: 24px;">
        CRITICAL FAILURE: The warning was bypassed. Scammer has exhausted banking assets to a burner handle.
      </p>
      <div style="background: rgba(255, 0, 85, 0.05); border: 1px solid rgba(255, 0, 85, 0.2); border-radius: 8px; width: 100%; padding: 14px; text-align: left; font-family:'JetBrains Mono'; font-size: 0.68rem; color:#ff9ca8;">
        <div>OUTFLOW STATUS: DRAINED</div>
        <div>LOST ASSETS: ₹${amt}</div>
        <div>UPI ID: ${currentTransactionIntercept.input.upiId}</div>
      </div>
      <button class="scam-pay-btn" onclick="location.reload()" style="background: var(--neon-pink); border: none; color: #fff; box-shadow:var(--neon-pink-glow); font-size: 0.75rem; margin-top:20px;">
        Restart Simulation
      </button>
    </div>
  `;
}

// Dynamic Audio Synthesizer (Zero assets required - pure cyber hackathon tech!)
function playAlertChime() {
  try {
    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    
    // Play double siren tones
    const playTone = (frequency, startTime, duration) => {
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(frequency, startTime);
      
      gain.gain.setValueAtTime(0.08, startTime);
      gain.gain.exponentialRampToValueAtTime(0.001, startTime + duration);
      
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      
      osc.start(startTime);
      osc.stop(startTime + duration);
    };

    const now = audioCtx.currentTime;
    playTone(330, now, 0.15);
    playTone(220, now + 0.12, 0.35);
  } catch (e) {
    console.log('WebAudio oscillator block or not supported:', e);
  }
}
