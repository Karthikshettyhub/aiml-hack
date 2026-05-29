// Heuristics Engine for Fraud Shield AI
// Pure JavaScript, deterministic risk analysis for ultra-fast, robust detection

/**
 * Analyze a URL for phishing and spoofing markers
 * @param {string} urlString - The URL to analyze
 * @returns {object} Analysis result containing score, suspicious flag, and indicators
 */
function analyzeURL(urlString) {
  const results = {
    isSuspicious: false,
    score: 0,
    indicators: [],
    details: {}
  };

  if (!urlString) return results;

  let url = urlString.trim();
  if (!/^https?:\/\//i.test(url)) {
    url = 'http://' + url;
  }

  try {
    const parsedUrl = new URL(url);
    const hostname = parsedUrl.hostname.toLowerCase();
    const pathname = parsedUrl.pathname.toLowerCase();
    const protocol = parsedUrl.protocol.toLowerCase();


    results.details.domain = hostname;
    results.details.path = pathname;
    results.details.protocol = protocol.replace(':', '');

    // 1. HTTPS Check
    if (protocol === 'http:') {
      results.score += 15;
      results.indicators.push({
        id: 'NO_HTTPS',
        name: 'Insecure Connection (No HTTPS)',
        severity: 'medium',
        description: 'The site does not use HTTPS encryption. Any passwords, card details, or UPI data entered will be transmitted in plain text.'
      });
      results.details.noHttps = true;
    }

    // 2. IP Address check
    const ipPattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (ipPattern.test(hostname)) {
      results.score += 35;
      results.indicators.push({
        id: 'IP_ADDRESS_URL',
        name: 'Raw IP Address Hostname',
        severity: 'high',
        description: 'The URL utilizes a raw IP address instead of a registered domain name. Scammers use raw IPs to host illegal backend sites without buying domain names.'
      });
      results.details.isIpAddress = true;
    }

    // 3. Suspicious TLD check
    const suspiciousTLDs = ['.ru', '.xyz', '.top', '.tk', '.fit', '.cn', '.cc', '.click', '.gq', '.cf', '.ga', '.ml', '.country', '.bid', '.buzz', '.monster', '.work', '.live', '.space', '.club', '.info'];
    const matchedTLD = suspiciousTLDs.find(tld => hostname.endsWith(tld));
    if (matchedTLD) {
      results.score += 25;
      results.indicators.push({
        id: 'SUSPICIOUS_TLD',
        name: `High-Risk TLD (${matchedTLD})`,
        severity: 'medium',
        description: `This website uses a low‑cost TLD (${matchedTLD}) often abused by scam sites.`
      });
      results.details.suspiciousTld = matchedTLD;
    }

    // 4. Shortened URL check
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd', 'rb.gy', 'rebrand.ly', 'tiny.cc', 't2mio.com', 'shorturl.at', 'git.io'];
    const isShortened = shorteners.some(s => hostname === s || hostname.endsWith('.' + s));
    if (isShortened) {
      results.score += 20;
      results.indicators.push({
        id: 'URL_SHORTENER',
        name: 'Link Redirection Masking',
        severity: 'medium',
        description: 'The URL is a shortened link, often used to hide malicious destinations.'
      });
      results.details.isShortened = true;
    }

    // 5. Brand impersonation detection
    const brandKeywords = ['paypal', 'paytm', 'gpay', 'phonepe', 'bofam', 'chase', 'wellsfargo', 'netflix', 'amazon', 'google', 'apple', 'microsoft', 'steam', 'coinbase', 'binance', 'metamask', 'sbi', 'hdfc', 'icici'];
    brandKeywords.forEach(brand => {
      const officialRegex = new RegExp(`^(${brand}\\.[a-z]{2,6}(\\.[a-z]{2})?)$`, 'i');
      const isOfficial = officialRegex.test(hostname) || hostname.endsWith(`.${brand}.com`) || hostname.endsWith(`.${brand}.in`);
      if (hostname.includes(brand) && !isOfficial) {
        results.score += 35;
        results.indicators.push({
          id: 'BRAND_IMPERSONATION',
          name: `Brand Impersonation (${brand})`,
          severity: 'high',
          description: `Domain contains brand name "${brand}" but is not an official site.`
        });
      }
    });

    // 6. Fake payment keywords
    const fakeKeywords = ['pay', 'secure', 'bank', 'login', 'verify', 'update', 'signin', 'billing', 'account', 'wallet', 'rewards', 'refund', 'claim', 'gift', 'crypto', 'cashback', 'bonus', 'free', 'support', 'helpdesk', 'safety', 'claims', 'redeem'];
    const foundKeywords = fakeKeywords.filter(k => hostname.includes(k) || pathname.includes(k));
    if (foundKeywords.length > 0) {
      const addedScore = Math.min(foundKeywords.length * 10, 30);
      results.score += addedScore;
      results.indicators.push({
        id: 'SCAM_KEYWORDS',
        name: 'Fraud‑Related Keywords Detected',
        severity: foundKeywords.length > 1 ? 'high' : 'medium',
        description: `URL contains suspicious terms (${foundKeywords.slice(0,3).join(', ')})`
      });
      results.details.foundKeywords = foundKeywords;
    }

    // 7. Payment pattern detection
    const paymentPatterns = ['pay', 'payment', 'transfer', 'checkout', 'deposit', 'withdraw', 'cash', 'refund'];
    const foundPayments = paymentPatterns.filter(p => hostname.includes(p) || pathname.includes(p));
    if (foundPayments.length > 0) {
      const addedScore = Math.min(foundPayments.length * 7, 20);
      results.score += addedScore;
      results.indicators.push({
        id: 'FAKE_PAYMENT_PATTERN',
        name: 'Financial‑Oriented Keyword Detected',
        severity: addedScore >= 15 ? 'high' : 'medium',
        description: `Payment‑related terms detected (${foundPayments.slice(0,3).join(', ')})`
      });
      results.details.paymentPatterns = foundPayments;
    }

    // 8. Excessive subdomains
    const parts = hostname.split('.');
    let domainPartsCount = parts.length;
    if (parts[0] === 'www') domainPartsCount--;
    if (domainPartsCount > 3) {
      results.score += 20;
      results.indicators.push({
        id: 'EXCESSIVE_SUBDOMAINS',
        name: 'Complex Subdomain Obfuscation',
        severity: 'medium',
        description: 'Too many subdomains hide the true host.'
      });
      results.details.subdomainCount = domainPartsCount;
    }

    // 9. Typosquatting detection
    const typosquattedTargets = [
      { official: 'paytm.com', patterns: [/payt[m-n]/, /payt[o-p]/, /p[a-e]ytm/, /paytma/, /payme/] },
      { official: 'paypal.com', patterns: [/payp[a-l]/, /payp[e-o]/, /p[a-e]ypal/, /paypal-/] },
      { official: 'google.com', patterns: [/go[o0]gle/, /g[o0]g[o0]le/, /gogle/] },
      { official: 'amazon.com', patterns: [/am[a-z]z[o0]n/, /amazn/, /amzon/] }
    ];
    typosquattedTargets.forEach(target => {
      const isOfficial = hostname === target.official || hostname.endsWith('.' + target.official);
      if (!isOfficial) {
        const matches = target.patterns.some(r => r.test(hostname));
        if (matches) {
          results.score += 40;
          results.indicators.push({
            id: 'TYPOSQUATTING',
            name: `Typosquatting of ${target.official}`,
            severity: 'high',
            description: `Domain mimics ${target.official}`
          });
        }
      }
    });

    // 10. Obfuscated characters
    if (hostname.includes('@') || hostname.includes('%') || hostname.includes('_')) {
      results.score += 25;
      results.indicators.push({
        id: 'OBFUSCATED_CHARACTERS',
        name: 'Obfuscated Hostname Characters',
        severity: 'high',
        description: 'Special symbols in hostname can hide the real domain.'
      });
      results.details.hasSpecialChars = true;
    }
  } catch (err) {
    results.score += 30;
    results.indicators.push({
      id: 'MALFORMED_URL',
      name: 'Malformed or Unparseable URL',
      severity: 'medium',
      description: 'Unable to parse URL, possible malicious construction.'
    });
  }

  results.score = Math.min(results.score, 100);
  results.isSuspicious = results.score >= 40;
  return results;
}

/**
 * Analyze a transaction for fraud indicators
 * @param {object} txData - Transaction details (amount, upiId, merchantName, note, repeatedAttempts, originUrl)
 * @param {object} [urlAnalysis] - Optional URL analysis from the source page
 * @returns {object} Analysis result containing score, suspicious flag, and indicators
 */
function analyzeTransaction(txData, urlAnalysis = null) {
  const results = {
    isSuspicious: false,
    score: 0,
    indicators: [],
    details: {}
  };

  const amount = parseFloat(txData.amount) || 0;
  const upiId = (txData.upiId || '').trim().toLowerCase();
  const merchantName = (txData.merchantName || '').trim();
  const note = (txData.note || '').trim().toLowerCase();
  const repeatedAttemptsCount = parseInt(txData.repeatedAttempts) || 0;

  // 1. Phishing-Origin Transaction link
  if (urlAnalysis && urlAnalysis.isSuspicious) {
    const penalty = urlAnalysis.score >= 70 ? 45 : 30;
    results.score += penalty;
    results.indicators.push({
      id: 'PHISHING_ORIGIN',
      name: 'Suspicious Web Portal Origin',
      severity: 'critical',
      description: `Transaction originates from a suspicious site (${txData.originUrl || 'unknown'}).`
    });
    results.details.originSuspicious = true;
  }

  // 2. Urgency keywords
  const urgencyKeywords = ['immediate', 'urgent', 'lock', 'block', 'suspend', 'verify', 'claim', 'refund', 'reward', 'cashback', 'lottery', 'winner', 'limit', 'warning', 'support', 'helpline', 'jackpot', 'prize', 'gift', 'bonus'];
  const matchedUrgency = urgencyKeywords.filter(k => note.includes(k) || merchantName.toLowerCase().includes(k));
  if (matchedUrgency.length > 0) {
    const addedScore = Math.min(matchedUrgency.length * 15, 40);
    results.score += addedScore;
    results.indicators.push({
      id: 'URGENCY_SCAM_KEYWORDS',
      name: 'Deceptive Social Engineering Text',
      severity: 'high',
      description: `Urgent wording detected (${matchedUrgency.slice(0,3).join(', ')})`
    });
    results.details.matchedUrgency = matchedUrgency;
  }

  // 3. High amount checks
  if (amount > 10000 && amount <= 100000) {
    results.score += 15;
    results.indicators.push({
      id: 'HIGH_AMOUNT',
      name: 'Elevated Transaction Value',
      severity: 'medium',
      description: `Amount ${amount.toLocaleString()} is unusually high.`
    });
    results.details.isHighAmount = true;
  } else if (amount > 100000) {
    results.score += 30;
    results.indicators.push({
      id: 'CRITICAL_HIGH_AMOUNT',
      name: 'Extremely High-Value Checkout',
      severity: 'high',
      description: `Amount ${amount.toLocaleString()} exceeds typical thresholds.`
    });
    results.details.isCriticalHighAmount = true;
  }

  // 4. Suspicious UPI handles
  if (upiId) {
    const scamUpiKeywords = ['claim', 'reward', 'refund', 'cashback', 'gift', 'prize', 'winner', 'lotto', 'admin', 'verify', 'support', 'bonus', 'helpdesk', 'safety'];
    const upiUser = upiId.split('@')[0] || '';
    const foundUpiKeywords = scamUpiKeywords.filter(k => upiUser.includes(k));
    if (foundUpiKeywords.length > 0) {
      results.score += 30;
      results.indicators.push({
        id: 'SCAM_UPI_KEYWORDS',
        name: 'Scam‑Simulating UPI ID Handle',
        severity: 'high',
        description: `UPI handle contains suspicious keyword (${foundUpiKeywords[0]})`
      });
    }
    const digitMatches = upiUser.match(/\d/g);
    const digitCount = digitMatches ? digitMatches.length : 0;
    if (digitCount >= 5) {
      results.score += 20;
      results.indicators.push({
        id: 'EXCESSIVE_UPI_DIGITS',
        name: 'Randomized Numeric UPI ID',
        severity: 'medium',
        description: 'UPI handle contains many numbers, typical of burner accounts.'
      });
    }
  }

  // 5. Fake merchant names
  const fakeMerchants = ['support desk', 'refund center', 'verification team', 'lottery admin', 'cashback unit', 'prize distribution', 'secure holding account', 'claim rewards inc'];
  const matchedFakeMerchant = fakeMerchants.find(m => merchantName.toLowerCase().includes(m));
  if (matchedFakeMerchant) {
    results.score += 35;
    results.indicators.push({
      id: 'FAKE_MERCHANT_NAME',
      name: 'Impersonated Administrative Merchant',
      severity: 'high',
      description: `Merchant name appears generic (${merchantName}).`
    });
  }

  // 6. Repeated attempts
  if (repeatedAttemptsCount > 1) {
    results.score += Math.min(repeatedAttemptsCount * 15, 45);
    results.indicators.push({
      id: 'REPEATED_ATTEMPTS',
      name: 'High‑Frequency Velocity Alert',
      severity: 'high',
      description: `${repeatedAttemptsCount} attempts within short timeframe.`
    });
  }

  results.score = Math.min(results.score, 100);
  results.isSuspicious = results.score >= 45;
  return results;
}

module.exports = {
  analyzeURL,
  analyzeTransaction
};
