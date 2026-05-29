// Express.js Backend Server for Fraud Shield AI
// Pure Node.js & Express API routes, with In-Memory telemetry tracking

const express = require('express');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const { analyzeURL, analyzeTransaction } = require('./heuristics');
const { generateThreatBrief } = require('./ai');

const app = express();
const PORT = process.env.PORT || 3000;

// Enable JSON parsing and CORS
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// In-Memory Database for Hackathon MVP
let threatLogs = [];

// Helper to seed gorgeous historical data for immediate dashboard impact
function seedDemoData() {
  const now = new Date();
  
  // Historical logs from the past 7 days
  const history = [
    {
      id: 'TH-001',
      timestamp: new Date(now.getTime() - 6 * 24 * 60 * 60 * 1000).toISOString(),
      type: 'url',
      input: 'http://whatsapp-verification-claims837.ru/login',
      score: 85,
      isSuspicious: true,
      indicators: [
        { name: 'Insecure Connection (No HTTPS)', description: 'The site does not use HTTPS encryption.' },
        { name: 'High-Risk TLD (.ru)', description: 'Uses Russian top-level domain commonly registered for spam.' },
        { name: 'Fraud Keywords', description: 'Contains billing keywords "verification", "claims".' }
      ],
      status: 'blocked'
    },
    {
      id: 'TH-002',
      timestamp: new Date(now.getTime() - 5 * 24 * 60 * 60 * 1000).toISOString(),
      type: 'transaction',
      input: {
        merchantName: 'Verification Desk Inc',
        amount: 25000,
        upiId: 'security-refund-verification@ybl',
        note: 'Immediate verification fee'
      },
      score: 95,
      isSuspicious: true,
      indicators: [
        { name: 'Social Engineering Urgency', description: 'Transaction notes pressure immediate execution.' },
        { name: 'Administrative Impersonation', description: 'Merchant uses a generic administrative desk title.' },
        { name: 'Scam-Mimicking UPI Handle', description: 'UPI handle mimics corporate payout servers.' }
      ],
      status: 'blocked'
    },
    {
      id: 'TH-003',
      timestamp: new Date(now.getTime() - 4 * 24 * 60 * 60 * 1000).toISOString(),
      type: 'url',
      input: 'https://paypal-support-billing.xyz/signin',
      score: 75,
      isSuspicious: true,
      indicators: [
        { name: 'Brand Impersonation (paypal)', description: 'Uses brand trademark without ownership.' },
        { name: 'High-Risk TLD (.xyz)', description: 'Uses .xyz domain frequently used by disposable portals.' }
      ],
      status: 'blocked'
    },
    {
      id: 'TH-004',
      timestamp: new Date(now.getTime() - 3 * 24 * 60 * 60 * 1000).toISOString(),
      type: 'transaction',
      input: {
        merchantName: 'Quick Reward Agency',
        amount: 5000,
        upiId: 'rewards-collect-8392@upi',
        note: 'Claim $500 Reward'
      },
      score: 55,
      isSuspicious: true,
      indicators: [
        { name: 'Psychological Urgency', description: 'Note references payout rewards.' },
        { name: 'Burner UPI Address', description: 'Recipient uses trailing numeric sequences.' }
      ],
      status: 'bypassed'
    },
    {
      id: 'TH-005',
      timestamp: new Date(now.getTime() - 2 * 24 * 60 * 60 * 1000).toISOString(),
      type: 'url',
      input: 'http://185.220.101.4/pay-securely',
      score: 65,
      isSuspicious: true,
      indicators: [
        { name: 'Raw IP Address Hostname', description: 'URL runs on bare IP instead of registered name.' },
        { name: 'Insecure Connection (No HTTPS)', description: 'Unencrypted communication pipeline.' }
      ],
      status: 'blocked'
    },
    {
      id: 'TH-006',
      timestamp: new Date(now.getTime() - 1 * 24 * 60 * 60 * 1000).toISOString(),
      type: 'transaction',
      input: {
        merchantName: 'Crypto Investment Hub',
        amount: 150000,
        upiId: 'deposit-verification-3829@apl',
        note: 'Urgent security escrow deposit'
      },
      score: 90,
      isSuspicious: true,
      indicators: [
        { name: 'Extremely High-Value Checkout', description: 'High-sum transfer to unverified source.' },
        { name: 'Urgency Social Engineering', description: 'Uses panic note keywords.' }
      ],
      status: 'blocked'
    }
  ];

  threatLogs = history;
}

seedDemoData();

// Calculate live aggregate stats for dashboard graphs
function getTelemetryStats() {
  const stats = {
    totalScanned: threatLogs.length,
    totalBlocked: threatLogs.filter(t => t.status === 'blocked' || t.status === 'aborted').length,
    totalBypassed: threatLogs.filter(t => t.status === 'bypassed').length,
    avgRiskScore: 0,
    byType: { url: 0, transaction: 0 },
    bySeverity: { critical: 0, high: 0, medium: 0 },
    dailyTrends: []
  };

  let totalScore = 0;
  
  // Calculate averages and breakouts
  threatLogs.forEach(log => {
    totalScore += log.score;
    if (log.type === 'url') stats.byType.url++;
    else stats.byType.transaction++;

    if (log.score >= 80) stats.bySeverity.critical++;
    else if (log.score >= 50) stats.bySeverity.high++;
    else stats.bySeverity.medium++;
  });

  stats.avgRiskScore = stats.totalScanned > 0 ? Math.round(totalScore / stats.totalScanned) : 0;

  // Generate 7-day trend arrays
  const last7Days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const dateStr = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    last7Days.push({
      date: dateStr,
      blocked: 0,
      scanned: 0,
      rawDate: d
    });
  }

  // Aggregate threats into days
  threatLogs.forEach(log => {
    const logDate = new Date(log.timestamp);
    const match = last7Days.find(day => {
      return logDate.getDate() === day.rawDate.getDate() && 
             logDate.getMonth() === day.rawDate.getMonth();
    });
    if (match) {
      match.scanned++;
      if (log.status === 'blocked' || log.status === 'aborted') {
        match.blocked++;
      }
    }
  });

  // Clean raw dates before sending to client
  stats.dailyTrends = last7Days.map(day => ({
    date: day.date,
    blocked: day.blocked,
    scanned: day.scanned
  }));

  return stats;
}

// REST API Endpoints

// 1. Get current threat logs and statistics
app.get('/api/threats', (req, res) => {
  try {
    const stats = getTelemetryStats();
    res.json({
      success: true,
      threats: threatLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)),
      stats
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 2. Scan URL logic
app.post('/api/scan-url', async (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ success: false, error: 'URL parameter is required.' });
  }

  try {
    const analysis = analyzeURL(url);
    // Always generate a threat brief (fallback will handle non-suspicious cases)
    const aiBrief = await generateThreatBrief('url', url, analysis);

    // Auto-log high-risk URLs as a scanned event (only when suspicious)
    if (analysis.isSuspicious) {
      const newThreat = {
        id: `TH-${Math.floor(100 + Math.random() * 900)}`,
        timestamp: new Date().toISOString(),
        type: 'url',
        input: url,
        score: analysis.score,
        isSuspicious: analysis.isSuspicious,
        indicators: analysis.indicators,
        aiBrief,
        status: 'blocked' // Default is blocked for URL scanners
      };
      
      threatLogs.push(newThreat);
    }

    res.json({
      success: true,
      analysis,
      aiBrief
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 3. Analyze Transaction logic
app.post('/api/analyze-transaction', async (req, res) => {
  const txData = req.body;
  if (!txData.amount || !txData.upiId) {
    return res.status(400).json({ success: false, error: 'Amount and UPI ID are required.' });
  }

  try {
    // If transaction mentions a source URL, check if that URL is suspicious
    let urlAnalysis = null;
    if (txData.originUrl) {
      urlAnalysis = analyzeURL(txData.originUrl);
    }

    const analysis = analyzeTransaction(txData, urlAnalysis);
    let aiBrief = '';

    if (analysis.isSuspicious) {
      aiBrief = await generateThreatBrief('transaction', txData, analysis);
    }

    // Return analysis details. We won't log it in memory immediately,
    // we wait for the client to tell us if the user aborted (blocked) or bypassed.
    res.json({
      success: true,
      analysis,
      aiBrief
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 4. Log a specific Threat outcome (user action)
app.post('/api/threats/log', (req, res) => {
  const { type, input, score, indicators, aiBrief, status } = req.body;

  try {
    const newThreat = {
      id: `TH-${Math.floor(100 + Math.random() * 900)}`,
      timestamp: new Date().toISOString(),
      type,
      input,
      score: parseInt(score) || 0,
      isSuspicious: true,
      indicators: Array.isArray(indicators) ? indicators : [],
      aiBrief: aiBrief || 'Threat successfully isolated.',
      status: status || 'blocked' // 'blocked', 'bypassed', 'aborted'
    };

    threatLogs.push(newThreat);
    
    // Keep in-memory store capped at 50 logs for stability
    if (threatLogs.length > 50) {
      threatLogs = threatLogs.slice(-50);
    }

    res.json({
      success: true,
      threat: newThreat,
      stats: getTelemetryStats()
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 5. Reset logs endpoint
app.post('/api/threats/reset', (req, res) => {
  try {
    seedDemoData();
    res.json({
      success: true,
      stats: getTelemetryStats()
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Catch-all route to serve the SPA frontend
app.get('/{*splat}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, () => {
  console.log(`\n========================================`);
  console.log(`🛡️  FRAUD SHIELD AI BACKEND INITIALIZED`);
  console.log(`🚀 Live port: http://localhost:${PORT}`);
  console.log(`========================================\n`);
});
