// AI Layer for Fraud Shield AI
// Integrates with Grok AI (X.AI) – uses local fallback when API key is missing/invalid

/**
 * Generates a cybersecurity threat brief explaining the risks to the user.
 * @param {string} type - Either 'url' or 'transaction'
 * @param {object} inputData - Original URL or transaction details
 * @param {object} analysis - The heuristic analysis result
 * @returns {Promise<string>} The cybersecurity markdown brief
 */
async function generateThreatBrief(type, inputData, analysis) {
  // ---- API key validation -------------------------------------------------
  const rawKey = process.env.GROK_API_KEY ? process.env.GROK_API_KEY.trim() : '';
  // Accept keys that look like "grok_..." (simple sanity check)
  const apiKey = rawKey && /^grok_[A-Za-z0-9_-]{10,}$/.test(rawKey) ? rawKey : '';
  const model = process.env.GROK_MODEL ? process.env.GROK_MODEL.trim() : 'grok-beta';

  // If no valid key → use local fallback immediately
  if (!apiKey) {
    return generateDynamicFallback(type, inputData, analysis);
  }

  // ---- Prompt preparation -------------------------------------------------
  const indicatorsText = analysis.indicators
    .map(i => `- **${i.name}**: ${i.description}`)
    .join('\n');
  const detailsJson = JSON.stringify(analysis.details, null, 2);

  const systemPrompt = `You are "Fraud Shield AI", an elite, real-time cybersecurity analyst agent safeguarding fintech users.
Your job is to analyze heuristic threat alerts and synthesize a high-impact, professional, educational, and easy-to-read "Threat Intelligence Brief" in clean Markdown.
Explain:
1. The exact attack vector or social engineering strategy (how the scam works, e.g., Typosquatting, Urgent Refund, Burner Account).
2. The psychological trick being played (greed, fear, artificial urgency).
3. Plain English breakdown of why our systems intercepted this (citing specific triggered indicators).
4. Direct, actionable cybersecurity advice on what the user should do next (e.g. abort, check official app, report domain).

Keep the brief concise, clean, and wowed with cybersecurity sophistication. Format with clear headings and bullet points. Tone should be alert, authoritative, and helpful. No fluff. Do not exceed 180 words.`;

  let userPrompt = '';
  if (type === 'url') {
    userPrompt = `[THREAT TYPE]: Phishing URL Detection
[URL SCANNING]: ${inputData}
[RISK SCORE]: ${analysis.score}/100
[HEURISTIC MARKERS TRIGGERED]:
${indicatorsText}

[DATA STREAM]:
${detailsJson}

Provide the brief immediately.`;
  } else {
    userPrompt = `[THREAT TYPE]: Suspicious P2P Transaction Intercept
[TRANSACTION DETAILS]:
- Merchant: ${inputData.merchantName || 'Unknown'}
- Amount: ${inputData.amount} INR/USD
- UPI ID / Recipient: ${inputData.upiId || 'Unknown'}
- Transaction Note: "${inputData.note || 'None'}"
- Origin Web Domain: ${inputData.originUrl || 'None'}
[RISK SCORE]: ${analysis.score}/100
[HEURISTIC MARKERS TRIGGERED]:
${indicatorsText}

[DATA STREAM]:
${detailsJson}

Provide the brief immediately.`;
  }

  // ---- Remote Grok call ---------------------------------------------------
  try {
    const response = await fetch('https://api.x.ai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt },
        ],
        temperature: 0.3,
      }),
    });

    if (response.ok) {
      const json = await response.json();
      if (json.choices && json.choices[0] && json.choices[0].message) {
        return json.choices[0].message.content.trim();
      }
    } else {
      console.error(`Grok API returned error: ${response.status} ${response.statusText}`);
    }
  } catch (err) {
    console.error('Grok API fetch error:', err.message);
  }

  // ---- Fallback -----------------------------------------------------------
  return generateDynamicFallback(type, inputData, analysis);
}

/**
 * Dynamic fallback generator creating identical high‑quality markdown security reviews
 */
function generateDynamicFallback(type, inputData, analysis) {
  const isHighRisk = analysis.score >= 70;
  const threatLevel = isHighRisk ? 'CRITICAL RISK' : 'ELEVATED RISK';
  let md = `### 🚨 FRAUD SHIELD AI: THREAT BRIEF (${threatLevel})\n\n`;

  if (type === 'url') {
    const domain = analysis.details.domain || 'Target Site';
    const isShortened = analysis.details.isShortened;
    const isIp = analysis.details.isIpAddress;
    const hasTyposquat = analysis.indicators.some(i => i.id === 'TYPOSQUATTING');
    const brandMatch = analysis.indicators.find(i => i.id && i.id.startsWith('BRAND_IMPERSONATION'));

    // 1️⃣ Attack vector
    if (brandMatch) {
      const brand = brandMatch.name.match(/\(([^)]+)\)/)?.[1] || 'trusted services';
      md += `**Attack Vector:** **Targeted Brand Impersonation Campaign**\n`;
      md += `The attacker has set up a fraudulent portal masquerading as **${brand}**. They are utilizing a copycat web interface to harvest your digital signatures, bank credentials, or UPI tokens.\n\n`;
    } else if (hasTyposquat) {
      md += `**Attack Vector:** **Typosquatting Homograph Attack**\n`;
      md += `The website uses a domain name that is slightly misspelled to mimic a well‑known financial portal. This relies on \"typosquatting\" — counting on users misreading the URL bar and entering sensitive details.\n\n`;
    } else if (isShortened) {
      md += `**Attack Vector:** **Redirect Obfuscation Masking**\n`;
      md += `This campaign hides a malicious destination behind an ephemeral shortener link to bypass firewalls and prevent initial secure scanner inspection.\n\n`;
    } else if (isIp) {
      md += `**Attack Vector:** **Direct IP Injection**\n`;
      md += `The website runs on a raw network IP instead of a registered domain. Scammers do this to spin up temporary malicious checkout panels that escape domain‑name registries.\n\n`;
    } else {
      md += `**Attack Vector:** **Deceptive Phishing Portal**\n`;
      md += `This webpage exhibits structural characteristics commonly found in disposable landing pages set up for data harvesting and fake financial collections.\n\n`;
    }

    // 2️⃣ Psychological trick
    md += `**Psychological Tactic:** **Credential/Fintech Harvesting**  \\n`;
    md += `By recreating a recognizable interface or hiding the destination URL, the attacker attempts to establish **artificial trust** so you will freely authorize access to your banking accounts.\n\n`;

    // 3️⃣ Technical breakdown
    md += `**Core Intercept Indicators:**\\n`;
    analysis.indicators.forEach(ind => {
      md += `- **${ind.name}**: ${ind.description}\\n`;
    });
    md += `\\n`;

    // 4️⃣ Actionable advice
    md += `**Security Countermeasures:**\\n`;
    md += `- **DO NOT ENTER DATA**: Immediately close this tab. Never supply card numbers, OTPs, or UPI PINs here.\\n`;
    md += `- **GO DIRECT**: If you need to access this brand, open a clean tab and manually type their official website address.\\n`;
    md += `- **REPORT**: Block the sender on WhatsApp/Email who shared this link.`;
  } else {
    // Transaction fallback (unchanged logic, just cleaned up formatting)
    const merchant = inputData.merchantName || 'Unknown Party';
    const amountStr = parseFloat(inputData.amount).toLocaleString();
    const upi = inputData.upiId || 'Unknown UPI';
    const hasPhishOrigin = analysis.indicators.some(i => i.id === 'PHISHING_ORIGIN');
    const hasUrgency = analysis.indicators.some(i => i.id === 'URGENCY_SCAM_KEYWORDS');
    const hasFakeMerch = analysis.indicators.some(i => i.id === 'FAKE_MERCHANT_NAME');

    if (hasPhishOrigin) {
      md += `**Attack Vector:** **Phishing‑Induced Push Payment Fraud**\\n`;
      md += `This payment is triggered directly by a hostile phishing site. The attacker used a fake checkout script to push an unauthorized transaction of **${amountStr}** to a burner account (${upi}).\\n\\n`;
    } else if (hasUrgency) {
      md += `**Attack Vector:** **Social Engineering Panic Loop**\\n`;
      md += `The scammer is utilizing high‑pressure keywords in the memo to trigger a sense of extreme panic (e.g. \"account block\") or greedy urgency (e.g. \"collect reward\").\\n\\n`;
    } else if (hasFakeMerch) {
      md += `**Attack Vector:** **Administrative Impersonation Scam**\\n`;
      md += `The recipient presents themselves as an official customer‑care, verification centre, or refund portal. They are doing this to spoof authority and deflect suspicion from the transaction.\\n\\n`;
    } else {
      md += `**Attack Vector:** **Suspicious P2P Payment Push**\\n`;
      md += `Our real‑time transaction engine intercepted a payment directed toward an unverified, high‑risk receiver account showing burner characteristics.\\n\\n`;
    }

    md += `**Psychological Tactic:** **Fear/Greed Exploitation**  \\n`;
    md += `Scammers use administrative titles or promise payouts to bypass your rational defenses, forcing you to authorize a transaction before taking time to verify it.\\n\\n`;

    md += `**Core Intercept Indicators:**\\n`;
    analysis.indicators.forEach(ind => {
      md += `- **${ind.name}**: ${ind.description}\\n`;
    });
    md += `\\n`;

    md += `**Security Countermeasures:**\\n`;
    md += `- **STOP TRANSACTION**: Abort immediately. Legitimate companies will **never** ask you to authorize a UPI/P2P transfer to claim a refund, prize, or prevent an account block.\\n`;
    md += `- **UPI PIN WARNING**: Remember, entering your UPI PIN is strictly for **sending money**, not receiving it.\\n`;
    md += `- **BLOCK ACCOUNT**: Flag the UPI ID \\${upi}\\ directly in your banking app.`;
  }

  return md;
}

module.exports = { generateThreatBrief };
