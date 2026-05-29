// popup.js – UI for the extension’s toolbar popup

const BACKEND_ORIGIN = 'http://localhost:3000';

// Helper to fetch dashboard stats
async function loadStats() {
  try {
    const resp = await fetch(`${BACKEND_ORIGIN}/api/threats`);
    const data = await resp.json();
    if (!data.success) throw new Error('API error');

    const { stats } = data;
    document.getElementById('stats').innerHTML = `
      📊 Blocked: ${stats.blocked}<br>
      📈 Scanned: ${stats.scanned}<br>
      ⏱️ Avg Score: ${stats.averageScore?.toFixed(1) ?? 0}
    `;
    document.getElementById('connection').textContent = '✅ Connected';
  } catch (e) {
    console.error(e);
    document.getElementById('connection').textContent = '❌ Cannot reach backend';
    document.getElementById('stats').textContent = '';
  }
}

// Open the full‑screen extension dashboard page
document.getElementById('openDashboard').addEventListener('click', () => {
  chrome.tabs.create({ url: `${BACKEND_ORIGIN}/extension-dashboard.html` });
});

// Initialise on load
loadStats();
