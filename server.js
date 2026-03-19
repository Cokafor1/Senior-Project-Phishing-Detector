const express = require('express');
const cors    = require('cors');
const axios   = require('axios');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.static('public'));

const VT_API_KEY     = process.env.VT_API_KEY;
const ANTHROPIC_KEY  = process.env.ANTHROPIC_API_KEY;
const VT_BASE        = 'https://www.virustotal.com/api/v3';
const ANTHROPIC_BASE = 'https://api.anthropic.com/v1/messages';

// ─── Helper: encode URL to VT base64url ──────────────────────────────────────
function vtUrlId(url) {
  return Buffer.from(url).toString('base64')
    .replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
}

// ─── Helper: parse email or bare domain ──────────────────────────────────────
function parseEmailInput(input) {
  const t = input.trim().toLowerCase();
  const em = t.match(/^[^@\s]+@([a-z0-9.\-]+\.[a-z]{2,})$/);
  if (em) return { domain: em[1], original: t, isEmail: true };
  const dm = t.match(/^([a-z0-9.\-]+\.[a-z]{2,})$/);
  if (dm) return { domain: dm[1], original: t, isEmail: false };
  return null;
}

// ─── Helper: majority vote from VT results ───────────────────────────────────
function majorityVote(stats) {
  const total      = Object.values(stats).reduce((a,b) => a+b, 0);
  const flagged    = stats.malicious + stats.suspicious;
  const clean      = stats.harmless + stats.undetected;
  const responding = total - (stats.timeout || 0);
  const majority   = Math.floor(responding / 2) + 1;
  const vote =
    stats.malicious >= majority ? 'DANGEROUS' :
    flagged >= majority         ? 'SUSPICIOUS' :
    stats.malicious > 0         ? 'SUSPICIOUS' :
    stats.suspicious > 0        ? 'SUSPICIOUS' : 'SAFE';
  return { vote, flagged, clean, total: responding,
    ratio: responding > 0 ? Math.round((flagged/responding)*100) : 0, stats };
}

// ─── Verdict from score ───────────────────────────────────────────────────────
function verdictFromScore(score) {
  if (score > 60) return 'DANGEROUS';
  if (score > 35) return 'SUSPICIOUS';
  if (score > 5) return 'CAUTION';
  return 'SAFE';
}

// ─── Domain + local part heuristics ──────────────────────────────────────────
function runHeuristics(domain, localPart) {
  const checks = [], tags = [];
  let score = 0;
  const d     = domain.toLowerCase();
  const local = (localPart || '').toLowerCase();
  const parts = d.split('.');

  const brands = ['google','amazon','facebook','paypal','apple','microsoft','netflix',
    'instagram','dropbox','linkedin','twitter','chase','wellsfargo','bankofamerica',
    'steam','ebay','spotify','adobe','coinbase','binance'];

  const freeDomains = ['gmail.com','yahoo.com','outlook.com','hotmail.com',
    'icloud.com','protonmail.com','proton.me','aol.com','live.com','msn.com'];

  // ── LOCAL PART CHECKS ───────────────────────────────────────────────────
  if (local) {
    const localBrandSpoof = brands.filter(b => local.includes(b));

    if (localBrandSpoof.length && freeDomains.includes(d)) {
      checks.push({ name:'Local Part Brand Spoof', icon:'🎭', status:'fail',
        detail:'"'+local+'" impersonates '+localBrandSpoof.join(', ')+' but sends from free provider '+d });
      score += 6; tags.push({ text:'Local Part Spoofing', type:'danger' });
    } else if (localBrandSpoof.length) {
      checks.push({ name:'Local Part Brand Spoof', icon:'🎭', status:'warn',
        detail:'Sender name contains brand "'+localBrandSpoof[0]+'" — verify this is really them' });
      score += 2; tags.push({ text:'Brand in Sender Name', type:'warn' });
    } else {
      checks.push({ name:'Local Part Brand Spoof', icon:'🎭', status:'pass',
        detail:'No brand names detected in the sender address' });
    }

    const localKws = ['billing','invoice','payment','refund','verify','security',
      'alert','noreply','no-reply','support','helpdesk','admin','service',
      'update','confirm','account','team','notification'];
    const localKwFound = localKws.filter(k => local.includes(k));

    if (localKwFound.length >= 2) {
      checks.push({ name:'Suspicious Sender Name', icon:'🎣', status:'fail',
        detail:'High-risk keywords in sender name: "'+localKwFound.slice(0,3).join('", "')+'"' });
      score += 3; tags.push({ text:'Suspicious Sender Name', type:'danger' });
    } else if (localKwFound.length === 1) {
      checks.push({ name:'Suspicious Sender Name', icon:'🎣', status:'warn',
        detail:'Keyword in sender name: "'+localKwFound[0]+'" — commonly used in phishing' });
      score += 1;
    } else {
      checks.push({ name:'Suspicious Sender Name', icon:'🎣', status:'pass',
        detail:'No suspicious keywords in sender name' });
    }

    const localBrand2 = brands.filter(b => local.includes(b));
    const localKw2    = localKws.filter(k => local.includes(k));
    if (freeDomains.includes(d) && (localBrand2.length || localKw2.length >= 1)) {
      checks.push({ name:'Free Provider Mismatch', icon:'📮', status:'fail',
        detail:'Legitimate companies never send billing or security emails from '+d });
      score += 4; tags.push({ text:'Free Email Impersonation', type:'danger' });
    } else if (freeDomains.includes(d)) {
      checks.push({ name:'Free Provider Mismatch', icon:'📮', status:'info',
        detail:'Sent from free provider ('+d+') — fine for personal, suspicious for business' });
    } else {
      checks.push({ name:'Free Provider Mismatch', icon:'📮', status:'pass',
        detail:'Uses a custom domain — consistent with a legitimate business sender' });
    }
  }

  // ── DOMAIN CHECKS ────────────────────────────────────────────────────────

  if (d.length > 40) {
    checks.push({ name:'Domain Length', icon:'📏', status:'fail', detail:d.length+' chars — unusually long' });
    score+=2; tags.push({ text:'Long Domain', type:'warn' });
  } else {
    checks.push({ name:'Domain Length', icon:'📏', status:'pass', detail:d.length+' chars — normal' });
  }

  const sub = parts.length - 2;
  if (sub > 3)      { checks.push({ name:'Subdomain Depth', icon:'🌿', status:'fail',  detail:sub+' levels deep' }); score+=3; tags.push({ text:'Deep Subdomains', type:'danger' }); }
  else if (sub > 1) { checks.push({ name:'Subdomain Depth', icon:'🌿', status:'warn',  detail:sub+' levels — worth checking' }); score+=1; }
  else              { checks.push({ name:'Subdomain Depth', icon:'🌿', status:'pass',  detail:sub+' subdomain level(s)' }); }

  const kws   = ['secure','verify','login','update','account','bank','paypal','confirm','support','service','helpdesk','billing','password','recover'];
  const found = kws.filter(k => d.includes(k));
  if (found.length >= 2)     { checks.push({ name:'Phishing Keywords', icon:'🎣', status:'fail', detail:'Found in domain: '+found.slice(0,4).join(', ') }); score+=3; tags.push({ text:'Phishing Keywords', type:'danger' }); }
  else if (found.length ===1){ checks.push({ name:'Phishing Keywords', icon:'🎣', status:'warn', detail:'Found in domain: '+found[0] }); score+=1; }
  else                       { checks.push({ name:'Phishing Keywords', icon:'🎣', status:'pass', detail:'No phishing keywords in domain' }); }

  const root    = parts.slice(-2).join('.');
  const spoofed = brands.filter(b => d.includes(b) && !root.startsWith(b));
  if (spoofed.length) { checks.push({ name:'Domain Brand Spoof', icon:'🏴', status:'fail', detail:'Domain impersonates: '+spoofed.join(', ') }); score+=4; tags.push({ text:'Brand Spoofing', type:'danger' }); }
  else                { checks.push({ name:'Domain Brand Spoof', icon:'🏴', status:'pass', detail:'No brand impersonation in domain' }); }

  const suspTlds = ['.xyz','.tk','.ml','.cf','.ga','.top','.click','.download','.gq','.pw','.icu','.buzz'];
  const tld      = '.'+parts[parts.length-1];
  if (suspTlds.includes(tld)) { checks.push({ name:'TLD Reputation', icon:'🏳️', status:'fail', detail:'"'+tld+'" — high-abuse TLD' }); score+=2; tags.push({ text:'Risky TLD', type:'warn' }); }
  else                        { checks.push({ name:'TLD Reputation', icon:'🏳️', status:'pass', detail:'"'+tld+'" — standard TLD' }); }

  const typos = [/0(?=[a-z])|(?<=[a-z])0/g, /1(?=l|i)|(?<=l|i)1/g, /rn(?=\b)/g];
  if (typos.some(p => p.test(d))) { checks.push({ name:'Typosquatting', icon:'🔤', status:'fail', detail:'Character substitution detected (e.g. 0 for o, rn for m)' }); score+=3; tags.push({ text:'Typosquatting', type:'danger' }); }
  else                             { checks.push({ name:'Typosquatting', icon:'🔤', status:'pass', detail:'No substitution patterns found' }); }

  const nums = (d.match(/\d/g)||[]).length;
  if (nums > 4) { checks.push({ name:'Numeric Characters', icon:'🔢', status:'warn', detail:nums+' digits — unusual for legit senders' }); score+=1; }
  else          { checks.push({ name:'Numeric Characters', icon:'🔢', status:'pass', detail:nums+' digit(s) — normal' }); }

  const hyphens = (d.match(/-/g)||[]).length;
  if (hyphens >= 3) { checks.push({ name:'Hyphen Count', icon:'➖', status:'fail', detail:hyphens+' hyphens — common in fake domains' }); score+=2; tags.push({ text:'Hyphen Abuse', type:'warn' }); }
  else              { checks.push({ name:'Hyphen Count', icon:'➖', status:'pass', detail:hyphens+' hyphen(s) — normal' }); }

  const safeDomains  = ['gmail.com','yahoo.com','outlook.com','hotmail.com','icloud.com',
    'apple.com','google.com','microsoft.com','amazon.com','github.com','proton.me','protonmail.com'];
  const isTrusted    = safeDomains.includes(d);
  const localRedFlags = local && (
    brands.filter(b => local.includes(b)).length > 0 ||
    ['billing','invoice','payment','verify','security','alert','support','helpdesk',
     'admin','confirm','account'].filter(k => local.includes(k)).length >= 1
  );

  if (isTrusted && !localRedFlags) {
    score = Math.max(0, score - 10);
    checks.push({ name:'Sender Reputation', icon:'⭐', status:'pass', detail:d+' is a well-known trusted domain' });
    tags.push({ text:'Trusted Domain', type:'info' });
  } else if (isTrusted && localRedFlags) {
    checks.push({ name:'Sender Reputation', icon:'⭐', status:'warn',
      detail:d+' is trusted but the sender name raises red flags — likely spoofed' });
  } else {
    checks.push({ name:'Sender Reputation', icon:'⭐', status:'info', detail:'Not in the trusted sender list' });
  }

  // ── CAUTION CHECKS: always-on observations even for clean domains ────────
  // These surface minor observations so SAFE never feels like "nothing to say"
  const cautionNotes = [];
  if (!isTrusted) cautionNotes.push({ name:'Unverified Sender', icon:'❓', status:'info',
    detail:'This domain has no established reputation in our trusted list. Verify the sender independently before clicking any links.' });
  if (local && !['billing','invoice','payment','refund','verify','security','alert',
    'noreply','no-reply','support','helpdesk','admin','service','update','confirm',
    'account','team','notification'].some(k => local.includes(k)) && !brands.some(b => local.includes(b))) {
    cautionNotes.push({ name:'Sender Name', icon:'👤', status:'info',
      detail:'Sender name "'+local+'" appears personal or generic — confirm you were expecting this email.' });
  }
  if (sub === 0) cautionNotes.push({ name:'No Subdomain', icon:'🌐', status:'info',
    detail:'Email sent directly from the root domain (no subdomain). Some phishing emails do this to appear simple and trustworthy.' });
  checks.push(...cautionNotes);

  return { score, maxScore: local ? 28 : 18, checks, tags, domain };
}

// ─── Email body pattern analysis ─────────────────────────────────────────────
function analyzeEmailBody(body, senderEmail, replyTo) {
  const flags = [];
  const text  = body.toLowerCase();
  let bodyScore = 0;

  const urgencyPhrases = ['act now','act immediately','urgent','immediately','expires','expiring',
    'last chance','limited time','within 24 hours','within 48 hours','account will be suspended',
    'account suspended','access will be revoked','respond immediately','failure to respond',
    'legal action','final notice','your account has been','has been compromised','unauthorized access'];
  const urgencyFound = urgencyPhrases.filter(p => text.includes(p));
  if (urgencyFound.length >= 2) {
    flags.push({ name:'Urgency Language', icon:'⏰', status:'fail',
      detail:'Detected: "'+urgencyFound.slice(0,3).join('", "')+'"',
      why:'Phishing emails manufacture urgency to pressure victims into acting before thinking.' });
    bodyScore += 25;
  } else if (urgencyFound.length === 1) {
    flags.push({ name:'Urgency Language', icon:'⏰', status:'warn',
      detail:'Detected: "'+urgencyFound[0]+'"',
      why:'Urgent language can indicate pressure tactics commonly used in phishing.' });
    bodyScore += 10;
  } else {
    flags.push({ name:'Urgency Language', icon:'⏰', status:'pass', detail:'No urgency phrases detected' });
  }

  const credPhrases = ['enter your password','confirm your password','verify your password',
    'enter your credit card','your social security','provide your account number',
    'confirm your details','update your billing','verify your identity',
    'enter your pin','banking details','click here to verify','click to confirm','click here to update'];
  const credFound = credPhrases.filter(p => text.includes(p));
  if (credFound.length >= 2) {
    flags.push({ name:'Credential Request', icon:'🔑', status:'fail',
      detail:'Requests sensitive info: "'+credFound.slice(0,2).join('", "')+'"',
      why:'Legitimate companies never ask for passwords, PINs, or card numbers via email.' });
    bodyScore += 35;
  } else if (credFound.length === 1) {
    flags.push({ name:'Credential Request', icon:'🔑', status:'fail',
      detail:'Requests: "'+credFound[0]+'"',
      why:'Legitimate companies never ask for passwords or sensitive data via email.' });
    bodyScore += 25;
  } else {
    flags.push({ name:'Credential Request', icon:'🔑', status:'pass', detail:'No credential requests detected' });
  }

  const urlPattern = /https?:\/\/[^\s"'<>]+/gi;
  const links      = body.match(urlPattern) || [];
  const suspLinkPatterns = [
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
    /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly/i,
    /\.xyz|\.tk|\.ml|\.top|\.click|\.icu/i,
    /login|verify|secure|update|account|confirm/i,
  ];
  const suspLinks = links.filter(l => suspLinkPatterns.some(p => p.test(l)));
  if (suspLinks.length > 0) {
    flags.push({ name:'Suspicious Links', icon:'🔗', status:'fail',
      detail:suspLinks.length+' suspicious link(s): '+suspLinks[0].substring(0,60)+'...',
      why:'Links with IP addresses, URL shorteners, or phishing keywords are a major red flag.' });
    bodyScore += 30;
  } else if (links.length > 0) {
    flags.push({ name:'Suspicious Links', icon:'🔗', status:'pass', detail:links.length+' link(s) found, none flagged' });
  } else {
    flags.push({ name:'Suspicious Links', icon:'🔗', status:'pass', detail:'No links found in body' });
  }

  const impersonationPhrases = ['dear customer','dear user','dear account holder','dear valued customer',
    'dear member','your apple id','your google account','your microsoft account','your paypal account',
    'your amazon account','your bank account','it department','help desk','security team',
    'dear [name]','dear {name}','hello [first name]'];
  const impFound = impersonationPhrases.filter(p => text.includes(p));
  if (impFound.length >= 2) {
    flags.push({ name:'Impersonation Phrases', icon:'🎭', status:'fail',
      detail:'Found: "'+impFound.slice(0,3).join('", "')+'"',
      why:'Generic greetings and brand name references are classic impersonation tactics.' });
    bodyScore += 20;
  } else if (impFound.length === 1) {
    flags.push({ name:'Impersonation Phrases', icon:'🎭', status:'warn',
      detail:'Found: "'+impFound[0]+'"',
      why:'Generic greetings may indicate a mass phishing campaign.' });
    bodyScore += 8;
  } else {
    flags.push({ name:'Impersonation Phrases', icon:'🎭', status:'pass', detail:'No impersonation phrases found' });
  }

  const grammarIndicators = [/\bplease to\b/i,/\bkindly do the needful\b/i,/[A-Z]{5,}/,/!{3,}/,/\${2,}/];
  const grammarFound = grammarIndicators.filter(p => p.test(body));
  if (grammarFound.length >= 2) {
    flags.push({ name:'Grammar Anomalies', icon:'✏️', status:'fail',
      detail:'Multiple grammar or formatting anomalies detected',
      why:'Poor grammar and excessive caps are common in phishing emails from auto-generators.' });
    bodyScore += 15;
  } else if (grammarFound.length === 1) {
    flags.push({ name:'Grammar Anomalies', icon:'✏️', status:'warn',
      detail:'Minor grammar or formatting anomaly detected' });
    bodyScore += 5;
  } else {
    flags.push({ name:'Grammar Anomalies', icon:'✏️', status:'pass', detail:'No obvious grammar anomalies' });
  }

  if (replyTo && senderEmail) {
    const senderDomain  = senderEmail.split('@')[1] || '';
    const replyToDomain = replyTo.trim().split('@')[1] || '';
    if (replyToDomain && senderDomain && replyToDomain !== senderDomain) {
      flags.push({ name:'Reply-To Mismatch', icon:'↩️', status:'fail',
        detail:'Sender: '+senderDomain+' vs Reply-To: '+replyToDomain,
        why:'A reply-to on a different domain means your reply goes to the attacker, not the apparent sender.' });
      bodyScore += 30;
    } else {
      flags.push({ name:'Reply-To Mismatch', icon:'↩️', status:'pass', detail:'Sender and reply-to domains match' });
    }
  } else {
    flags.push({ name:'Reply-To Mismatch', icon:'↩️', status:'info', detail:'No reply-to address provided to compare' });
  }

  return { flags, bodyScore, links: links.length, suspiciousLinks: suspLinks };
}

// ─── Claude AI analysis ───────────────────────────────────────────────────────
async function analyzeWithClaude(emailBody, senderEmail, domain, patternFlags) {
  if (!ANTHROPIC_KEY) return { success: false, reason: 'No Anthropic API key configured' };
  const flagSummary = patternFlags
    .filter(f => f.status === 'fail' || f.status === 'warn')
    .map(f => '- '+f.name+': '+f.detail).join('\n') || 'None detected';
  try {
    const response = await axios.post(ANTHROPIC_BASE, {
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      system: 'You are a cybersecurity expert specializing in phishing email detection. Analyze email content and return ONLY a valid JSON object with no extra text, no markdown, no code fences.',
      messages: [{
        role: 'user',
        content: `Analyze this email for phishing indicators.\n\nSender: ${senderEmail||'unknown'}\nDomain: ${domain}\nPattern flags:\n${flagSummary}\n\nEmail body:\n---\n${emailBody.substring(0,3000)}\n---\n\nReturn ONLY this JSON:\n{\n  "verdict": "SAFE"|"CAUTION"|"SUSPICIOUS"|"DANGEROUS",\n  "confidence": "low"|"medium"|"high",\n  "summary": "2-3 sentence plain English summary",\n  "redFlags": ["red flag 1"],\n  "legitimacyIndicators": ["legit indicator 1"],\n  "recommendation": "One clear action sentence"\n}`
      }]
    }, {
      headers: { 'x-api-key': ANTHROPIC_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      timeout: 20000
    });
    const raw    = response.data.content[0].text.trim();
    const parsed = JSON.parse(raw.replace(/```json|```/g,'').trim());
    return { success: true, ...parsed };
  } catch(err) {
    return { success: false, reason: err.message };
  }
}

// ─── POST /analyze ────────────────────────────────────────────────────────────
app.post('/analyze', async (req, res) => {
  const { email, emailBody, replyTo } = req.body;
  if (!email) return res.status(400).json({ error: 'Email address is required' });

  const parsed = parseEmailInput(email);
  if (!parsed) return res.status(400).json({ error: 'Invalid input. Please enter a valid email address.' });

  const { domain, original, isEmail } = parsed;
  const domainUrl = 'https://' + domain;
  const localPart = isEmail ? original.split('@')[0] : '';

  const heuristics = runHeuristics(domain, localPart);
  heuristics.email   = original;
  heuristics.domain  = domain;
  heuristics.isEmail = isEmail;

  let bodyAnalysis = null;
  let aiAnalysis   = null;
  if (emailBody && emailBody.trim().length > 10) {
    bodyAnalysis = analyzeEmailBody(emailBody.trim(), original, replyTo || '');
    aiAnalysis   = analyzeWithClaude(emailBody.trim(), original, domain, bodyAnalysis.flags);
  }

  // No VT key — heuristics only
  if (!VT_API_KEY) {
    const ai         = await (aiAnalysis || Promise.resolve(null));
    if (bodyAnalysis) bodyAnalysis.ai = ai;
    const bodyContrib = bodyAnalysis ? Math.min(40, Math.round(bodyAnalysis.bodyScore * 0.4)) : 0;
    const rawScore   = Math.round((heuristics.score / heuristics.maxScore) * 60) + bodyContrib;
    const score      = Math.min(100, rawScore);
    const verdict    = verdictFromScore(score);
    return res.json({
      email: original, domain, verdict, score,
      source: 'heuristics_only', heuristics, bodyAnalysis,
      virustotal: null, engines: [],
      summary: buildSummary(verdict, null, domain, bodyAnalysis)
    });
  }

  try {
    const urlId = vtUrlId(domainUrl);
    let vtData;
    try {
      const cached = await axios.get(`${VT_BASE}/urls/${urlId}`, { headers:{ 'x-apikey':VT_API_KEY } });
      vtData = cached.data;
    } catch(e) {
      const sub = await axios.post(`${VT_BASE}/urls`,
        new URLSearchParams({ url: domainUrl }),
        { headers:{ 'x-apikey':VT_API_KEY, 'Content-Type':'application/x-www-form-urlencoded' } });
      const aid = sub.data.data.id;
      for (let i=0; i<5; i++) {
        await new Promise(r => setTimeout(r,3000));
        const poll = await axios.get(`${VT_BASE}/analyses/${aid}`, { headers:{ 'x-apikey':VT_API_KEY } });
        if (poll.data.data.attributes.status === 'completed') {
          const full = await axios.get(`${VT_BASE}/urls/${urlId}`, { headers:{ 'x-apikey':VT_API_KEY } });
          vtData = full.data; break;
        }
      }
    }

    if (!vtData) throw new Error('Engine analysis timed out');

    const ai = await (aiAnalysis || Promise.resolve(null));
    if (bodyAnalysis) bodyAnalysis.ai = ai;

    const attrs  = vtData.data.attributes;
    const stats  = attrs.last_analysis_stats;
    const result = majorityVote(stats);

    // Heuristic score as a 0-100 value
    const hScore      = Math.round((heuristics.score / heuristics.maxScore) * 100);
    const bodyContrib = bodyAnalysis ? Math.min(20, Math.round(bodyAnalysis.bodyScore * 0.2)) : 0;

    // VT contributes up to 60 pts, heuristics always contribute their full value (up to 30 pts),
    // body contributes up to 20 pts. This ensures heuristics are NEVER washed out by a clean VT.
    const vtContrib  = Math.round(result.ratio * 0.6);
    const finalScore = Math.min(100, vtContrib + Math.round(hScore * 0.3) + bodyContrib);

    // Score is the single authority for verdict — VT can only escalate, never suppress
    let finalVerdict = verdictFromScore(finalScore);
    if (result.vote === 'SUSPICIOUS' && finalVerdict === 'CAUTION') finalVerdict = 'SUSPICIOUS';
    if (result.vote === 'SUSPICIOUS' && finalVerdict === 'SAFE')    finalVerdict = 'CAUTION';
    if (result.vote === 'DANGEROUS')                                 finalVerdict = 'DANGEROUS';
    if (ai && ai.success && ai.verdict === 'DANGEROUS' && finalVerdict !== 'DANGEROUS') finalVerdict = 'SUSPICIOUS';

    const engineResults = Object.entries(attrs.last_analysis_results || {})
      .map(([engine, d]) => ({ engine, category: d.category, result: d.result }))
      .sort((a,b) =>
        ({'malicious':0,'suspicious':1,'harmless':2,'undetected':3}[a.category]??4) -
        ({'malicious':0,'suspicious':1,'harmless':2,'undetected':3}[b.category]??4));

    res.json({
      email: original, domain, verdict: finalVerdict,
      score: finalScore, source: 'virustotal',
      heuristics, bodyAnalysis,
      virustotal: {
        stats, vote: result, reputation: attrs.reputation ?? null,
        categories: attrs.categories ?? {},
        lastAnalysisDate: attrs.last_analysis_date
          ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
      },
      engines: engineResults,
      summary: buildSummary(finalVerdict, result, domain, bodyAnalysis)
    });

  } catch(err) {
    console.error('Engine error:', err.response?.data || err.message);
    const ai = await (aiAnalysis || Promise.resolve(null));
    if (bodyAnalysis) bodyAnalysis.ai = ai;
    const bodyContrib = bodyAnalysis ? Math.min(20, Math.round(bodyAnalysis.bodyScore * 0.2)) : 0;
    const rawScore    = Math.round((heuristics.score / heuristics.maxScore) * 80) + bodyContrib;
    const score       = Math.min(100, rawScore);
    const verdict     = verdictFromScore(score);
    res.json({
      email: original, domain, verdict, score,
      source: 'heuristics_fallback', heuristics, bodyAnalysis,
      virustotal: null, engines: [],
      summary: buildSummary(verdict, null, domain, bodyAnalysis)
    });
  }
});

// ─── Build summary text ───────────────────────────────────────────────────────
function buildSummary(verdict, vtResult, domain, bodyAnalysis) {
  const bodyNote = bodyAnalysis ? ' Email body analysis was included.' : '';
  const vtNote   = vtResult
    ? `Scanned by ${vtResult.total} engines — ${vtResult.flagged} flagged this domain.`
    : 'No engine scan available.';
  const verdictMessages = {
    SAFE:       `${vtNote} No significant threats detected for "${domain}". Always verify senders you weren't expecting.${bodyNote}`,
    CAUTION:    `${vtNote} "${domain}" passed engine checks but has minor indicators worth noting. Review carefully before clicking any links.${bodyNote}`,
    SUSPICIOUS: `${vtNote} "${domain}" shows suspicious characteristics. Do not click links or provide any personal information.${bodyNote}`,
    DANGEROUS:  `${vtNote} "${domain}" is flagged as malicious. This is likely a phishing attempt — do NOT interact with this email.${bodyNote}`,
  };
  return verdictMessages[verdict] || verdictMessages['CAUTION'];
}

app.get('/health', (req, res) => res.json({ status:'ok', vtConfigured:!!VT_API_KEY, aiConfigured:!!ANTHROPIC_KEY }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Phish Me running on http://localhost:${PORT}`));