/**
 * SecureSight risk engine
 * -----------------------
 * 1. extractUrlFeatures(url)   -> numeric features from the URL alone (also used for ML training)
 * 2. urlRisk(url, model?)      -> 0-100 URL score (rule-based, or logistic regression if a model is supplied)
 * 3. computeRisk(signals, ...) -> weighted 0-100 verdict combining URL score + live checks
 *
 * Missing live checks are treated as unknown (score scaled by the checks that ran), never as safe.
 *
 * Works in three places with no changes: the popup (<script>), a service worker
 * (importScripts) and Node (require) for offline evaluation.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.RiskEngine = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // ------------------------------------------------------------------ reference data
  const BRANDS = [
    "google", "gmail", "paypal", "facebook", "instagram", "whatsapp", "amazon", "apple", "icloud",
    "microsoft", "outlook", "office365", "netflix", "linkedin", "twitter", "github", "dropbox",
    "yahoo", "ebay", "adobe", "spotify", "paytm", "phonepe", "flipkart", "irctc", "sbi",
    "hdfcbank", "icicibank", "axisbank", "kotak", "binance", "coinbase", "metamask",
  ];
  const SUSPICIOUS_TLDS = new Set([
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "loan", "win", "click", "support", "review",
    "work", "zip", "mov", "country", "kim", "men", "party", "stream", "download", "racing",
  ]);
  const SHORTENERS = new Set([
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
  ]);
  const KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure", "account", "update", "confirm",
    "banking", "password", "wallet", "suspend", "unlock", "billing", "payment", "support", "alert",
  ];
  // Real domains owned by the brands above. Prevents false alarms such as login.microsoftonline.com.
  const BRAND_OWNED = new Set([
    "google.com", "google.co.in", "googleapis.com", "gstatic.com", "googleusercontent.com", "youtube.com", "gmail.com",
    "microsoft.com", "microsoftonline.com", "live.com", "office.com", "office365.com", "outlook.com", "bing.com",
    "amazon.com", "amazon.in", "amazonaws.com", "apple.com", "icloud.com", "paypal.com", "paypal.me",
    "facebook.com", "instagram.com", "whatsapp.com", "meta.com", "linkedin.com", "twitter.com", "x.com",
    "github.com", "githubusercontent.com", "github.io", "netflix.com", "spotify.com", "adobe.com", "dropbox.com",
    "yahoo.com", "ebay.com", "paytm.com", "phonepe.com", "flipkart.com", "irctc.co.in",
    "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com", "axisbank.com", "kotak.com",
    "binance.com", "coinbase.com", "metamask.io",
  ]);
  // Second-level labels that act like a TLD (co.uk, com.au, co.in ...). Approximation of the Public Suffix List.
  const SECOND_LEVEL = new Set(["co", "com", "org", "net", "gov", "edu", "ac", "nic", "res", "ltd"]);

  // ------------------------------------------------------------------ helpers
  function parseUrl(raw) {
    if (typeof raw !== "string") return null;
    const s = raw.trim();
    if (!s) return null;
    try {
      return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : "http://" + s);
    } catch (e) {
      return null;
    }
  }

  function entropy(str) {
    if (!str) return 0;
    const counts = {};
    for (const ch of str) counts[ch] = (counts[ch] || 0) + 1;
    let h = 0;
    for (const k in counts) {
      const p = counts[k] / str.length;
      h -= p * Math.log2(p);
    }
    return h;
  }

  function levenshtein(a, b) {
    const m = a.length, n = b.length;
    if (!m) return n;
    if (!n) return m;
    let prev = Array.from({ length: n + 1 }, (_, j) => j);
    for (let i = 1; i <= m; i++) {
      const cur = [i];
      for (let j = 1; j <= n; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
      prev = cur;
    }
    return prev[n];
  }

  // Undo common digit-for-letter swaps used in look-alike domains: paypa1 -> paypal, g00gle -> google
  function deLeet(s) {
    return s.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/5/g, "s").replace(/@/g, "a");
  }

  function splitHost(host) {
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":");
    if (isIp) return { isIp: true, domain: host, label: host, tld: "", subdomains: [] };
    const labels = host.split(".").filter(Boolean);
    const tld = labels[labels.length - 1] || "";
    let take = 2;
    if (labels.length >= 3 && tld.length === 2 && SECOND_LEVEL.has(labels[labels.length - 2])) take = 3;
    take = Math.min(take, labels.length);
    const domainLabels = labels.slice(labels.length - take);
    return {
      isIp: false,
      domain: domainLabels.join("."),
      label: domainLabels[0],
      tld,
      subdomains: labels.slice(0, labels.length - take),
    };
  }

  // Returns true if the registrable label is a near-miss of a known brand (but not the brand itself)
  function isTyposquat(label, domain) {
    if (!label || label.length < 4) return false;
    if (domain && BRAND_OWNED.has(domain)) return false;
    const norm = deLeet(label);
    for (const brand of BRANDS) {
      if (label === brand) return false; // genuine brand label
    }
    for (const brand of BRANDS) {
      if (norm === brand) return true; // pure digit-substitution (paypa1, g00gle)
      if (brand.length < 5) continue; // short brands only match exactly (avoids false positives)
      const d = levenshtein(norm, brand);
      if (d >= 1 && d <= (brand.length >= 8 ? 2 : 1)) return true;
    }
    return false;
  }

  // Brand name appears in subdomain/path/hyphenated label while the real registrable domain is something else
  function brandImpersonation(parts, pathAndQuery) {
    const label = parts.label;
    if (BRANDS.includes(label) || BRAND_OWNED.has(parts.domain)) return false;
    const hay = deLeet((parts.subdomains.join(".") + " " + label + " " + pathAndQuery).toLowerCase());
    const tokens = hay.split(/[^a-z0-9]+/);
    // long brands: substring match; short brands (sbi, ebay): whole-token match to avoid false hits
    return BRANDS.some((b) => (b.length >= 5 ? hay.includes(b) : tokens.includes(b)));
  }

  // ------------------------------------------------------------------ 1. feature extraction
  const FEATURE_NAMES = [
    "urlLength", "hostLength", "pathLength", "queryLength", "dotCount", "subdomainCount",
    "hyphenCount", "digitRatioHost", "specialCharCount", "hasAt", "isIp", "hasPunycode",
    "hasNonAscii", "hostEntropy", "pathDepth", "notHttps", "suspiciousTld", "keywordHits",
    "brandImpersonation", "typosquat", "isShortener", "hasPort", "encodedChars", "doubleSlashInPath",
  ];

  function extractUrlFeatures(rawUrl) {
    const u = parseUrl(rawUrl);
    if (!u) return null;
    const host = u.hostname.toLowerCase();
    const parts = splitHost(host);
    const path = u.pathname || "";
    const query = u.search || "";
    const full = String(rawUrl).trim();
    const pathAndQuery = (path + query).toLowerCase();
    const hostDigits = (host.match(/\d/g) || []).length;

    let keywordHits = 0;
    const lowerAll = (host + pathAndQuery).toLowerCase();
    for (const k of KEYWORDS) if (lowerAll.includes(k)) keywordHits++;

    return {
      urlLength: full.length,
      hostLength: host.length,
      pathLength: path.length,
      queryLength: query.length,
      dotCount: (host.match(/\./g) || []).length,
      subdomainCount: parts.subdomains.length,
      hyphenCount: (host.match(/-/g) || []).length,
      digitRatioHost: host.length ? hostDigits / host.length : 0,
      specialCharCount: (full.match(/[@?&=_%~#]/g) || []).length,
      hasAt: /@/.test(full.split("?")[0].replace(/^[a-z]+:\/\//i, "").split("/")[0]) ? 1 : 0,
      isIp: parts.isIp ? 1 : 0,
      hasPunycode: host.split(".").some((l) => l.startsWith("xn--")) ? 1 : 0,
      hasNonAscii: /[^\x00-\x7F]/.test(full) ? 1 : 0,
      hostEntropy: entropy(host),
      pathDepth: path.split("/").filter(Boolean).length,
      notHttps: u.protocol === "https:" ? 0 : 1,
      suspiciousTld: SUSPICIOUS_TLDS.has(parts.tld) ? 1 : 0,
      keywordHits,
      brandImpersonation: !parts.isIp && brandImpersonation(parts, pathAndQuery) ? 1 : 0,
      typosquat: !parts.isIp && isTyposquat(parts.label, parts.domain) ? 1 : 0,
      isShortener: SHORTENERS.has(parts.domain) ? 1 : 0,
      hasPort: u.port ? 1 : 0,
      encodedChars: (full.match(/%[0-9a-f]{2}/gi) || []).length,
      doubleSlashInPath: path.includes("//") ? 1 : 0,
    };
  }

  // ------------------------------------------------------------------ 2. URL risk (rules or ML)
  // [id, predicate, points, human-readable reason]
  const URL_RULES = [
    ["typosquat", (f) => f.typosquat, 30, "Domain looks like a misspelling of a well-known brand"],
    ["brandImpersonation", (f) => f.brandImpersonation, 25, "Brand name used in a domain that does not belong to the brand"],
    ["isIp", (f) => f.isIp, 25, "Uses a raw IP address instead of a domain name"],
    ["hasPunycode", (f) => f.hasPunycode, 25, "Internationalised (punycode) domain, a common look-alike trick"],
    ["hasAt", (f) => f.hasAt, 15, "Contains '@' which can hide the real destination"],
    ["suspiciousTld", (f) => f.suspiciousTld, 15, "Top-level domain often abused for phishing"],
    ["isShortener", (f) => f.isShortener, 10, "Link shortener hides the real destination"],
    ["keywords", (f) => Math.min(f.keywordHits, 3) > 0, null, "Sensitive keywords in the URL (login, verify, account...)"],
    ["subdomains", (f) => f.subdomainCount >= 3, 10, "Unusually many subdomains"],
    ["hyphens", (f) => f.hyphenCount >= 2, 8, "Several hyphens in the domain"],
    ["longHost", (f) => f.hostLength > 30, 8, "Very long domain name"],
    ["digits", (f) => f.digitRatioHost > 0.3, 8, "Many digits in the domain"],
    ["entropy", (f) => f.hostEntropy > 3.8, 6, "Random-looking domain name"],
    ["longUrl", (f) => f.urlLength > 100, 8, "Very long URL"],
    ["notHttps", (f) => f.notHttps, 8, "Page is not served over HTTPS"],
    ["port", (f) => f.hasPort, 5, "Non-standard port"],
    ["encoded", (f) => f.encodedChars > 3, 5, "Heavily percent-encoded URL"],
    ["doubleSlash", (f) => f.doubleSlashInPath, 5, "Double slash in the path"],
  ];

  function sigmoid(z) {
    return 1 / (1 + Math.exp(-z));
  }

  function urlRisk(rawUrl, model) {
    const f = extractUrlFeatures(rawUrl);
    if (!f) return { score: 0, source: "none", features: null, reasons: [], valid: false };

    if (model && Array.isArray(model.features)) {
      let z = model.bias;
      const contrib = [];
      model.features.forEach((name, i) => {
        const std = model.std[i] || 1;
        const c = (model.weights[i] * ((f[name] || 0) - model.mean[i])) / std;
        z += c;
        contrib.push({ name, c });
      });
      const p = sigmoid(z);
      const reasons = contrib
        .filter((x) => x.c > 0.3)
        .sort((a, b) => b.c - a.c)
        .slice(0, 3)
        .map((x) => ({ label: "Model signal: " + x.name, points: Math.round(x.c * 10) / 10 }));
      return { score: Math.round(p * 100), probability: p, source: "model", features: f, reasons, valid: true };
    }

    let total = 0;
    const reasons = [];
    for (const [id, test, pts, label] of URL_RULES) {
      if (!test(f)) continue;
      const points = id === "keywords" ? Math.min(f.keywordHits, 3) * 6 : pts;
      total += points;
      reasons.push({ label, points });
    }
    return { score: Math.min(100, total), source: "rules", features: f, reasons, valid: true };
  }

  // ------------------------------------------------------------------ 3. weighted verdict
  // Maximum contribution of each signal to the final 0-100 score (sums to 100).
  const WEIGHTS = { url: 35, domainAge: 25, ssl: 20, scripts: 10, links: 10 };
  const SAFE_BROWSING_FLOOR = 90; // a Safe Browsing hit is near-certain, so it overrides the sum

  function levelFor(score) {
    if (score >= 60) return "High";
    if (score >= 30) return "Medium";
    return "Low";
  }

  /**
   * signals = {
   *   url: string,
   *   domainAgeDays: number|null,
   *   ssl: { valid: true|false|null } | null,
   *   safeBrowsingThreat: true|false|null,     // true = flagged, null = check unavailable
   *   suspiciousScripts: true|false|null,
   *   suspiciousLinks: { high:number, medium:number } | null
   * }
   */
  function computeRisk(signals, opts) {
    const model = opts && opts.model;
    const reasons = [];
    const missing = [];
    let score = 0;
    // Missing checks mean "unknown", not "safe": the score is scaled by the weight of the checks that
    // actually ran, so a phishy URL is not hidden just because WHOIS/SSL have not returned yet.
    let availableMax = WEIGHTS.url;

    const u = urlRisk(signals.url, model);
    const urlPoints = Math.round((u.score / 100) * WEIGHTS.url);
    score += urlPoints;
    u.reasons.slice(0, 4).forEach((r) => reasons.push({ label: r.label, points: Math.round((r.points / 100) * WEIGHTS.url * 10) / 10 || 1 }));

    const age = signals.domainAgeDays;
    if (typeof age === "number" && isFinite(age)) {
      availableMax += WEIGHTS.domainAge;
      let p = 0;
      if (age < 7) p = 25;
      else if (age < 30) p = 20;
      else if (age < 90) p = 12;
      else if (age < 365) p = 5;
      if (p) {
        score += p;
        reasons.push({ label: `Domain registered only ${Math.max(0, Math.floor(age))} days ago`, points: p });
      }
    } else missing.push("domain age");

    const ssl = signals.ssl;
    if (ssl && (ssl.valid === true || ssl.valid === false)) {
      availableMax += WEIGHTS.ssl;
      if (ssl.valid === false) {
        score += WEIGHTS.ssl;
        reasons.push({ label: "Invalid or expired SSL certificate", points: WEIGHTS.ssl });
      }
    } else missing.push("SSL");

    if (signals.suspiciousScripts === true || signals.suspiciousScripts === false) {
      availableMax += WEIGHTS.scripts;
      if (signals.suspiciousScripts) {
        score += WEIGHTS.scripts;
        reasons.push({ label: "Suspicious scripts found on the page", points: WEIGHTS.scripts });
      }
    } else missing.push("page scripts");

    const links = signals.suspiciousLinks;
    if (links) {
      availableMax += WEIGHTS.links;
      if (links.high > 0) {
        score += WEIGHTS.links;
        reasons.push({ label: `${links.high} high-risk link(s) on the page`, points: WEIGHTS.links });
      } else if (links.medium > 0) {
        score += WEIGHTS.links / 2;
        reasons.push({ label: `${links.medium} medium-risk link(s) on the page`, points: WEIGHTS.links / 2 });
      }
    } else missing.push("page links");

    if (signals.safeBrowsingThreat === true) {
      reasons.unshift({ label: "Flagged by Google Safe Browsing", points: SAFE_BROWSING_FLOOR });
    } else if (signals.safeBrowsingThreat === null || signals.safeBrowsingThreat === undefined) missing.push("Safe Browsing");

    score = Math.round((score / availableMax) * 100);
    if (signals.safeBrowsingThreat === true && score < SAFE_BROWSING_FLOOR) score = SAFE_BROWSING_FLOOR;
    score = Math.max(0, Math.min(100, score));
    const liveChecks = 5;
    const confidence = Math.round(((liveChecks - missing.length) / liveChecks) * 100) / 100;

    reasons.sort((a, b) => b.points - a.points);
    return { score, level: levelFor(score), confidence, missing, reasons, urlScore: u.score, urlSource: u.source };
  }

  return { FEATURE_NAMES, extractUrlFeatures, urlRisk, computeRisk, WEIGHTS, levelFor, _internal: { levenshtein, deLeet, splitHost, entropy, isTyposquat } };
});
