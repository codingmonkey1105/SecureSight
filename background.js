// Runs once when the extension is installed
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log("SecureSight extension installed.");
  
  // Only seed on fresh install or update
  if (details.reason === 'install' || details.reason === 'update') {
    console.log("🔄 Auto-seeding favicon whitelist...");
    
    // Define your trusted domains
    const trustedDomains = [
      //{ domain: "https://www.google.com", label: "Google" },
      //{ domain: "https://www.github.com", label: "GitHub" },
      { domain: "https://www.amazon.com", label: "Amazon" }//,
      //{ domain: "https://www.paypal.com", label: "PayPal" },
      //{ domain: "https://www.facebook.com", label: "Facebook" },
      //{ domain: "https://www.netflix.com", label: "Netflix" },
      //{ domain: "https://www.linkedin.com", label: "LinkedIn" },
      //{ domain: "https://www.twitter.com", label: "Twitter" },
      //{ domain: "https://www.microsoft.com", label: "Microsoft" },
      //{ domain: "https://www.apple.com", label: "Apple" }
    ];
    
    // Auto-seed the whitelist
    await autoSeedFaviconWhitelist(trustedDomains);
  }
});

// ===== API KEY (YOU NEED TO ADD THIS) =====
const GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyAS3hoD7cE_aGaUKJu8xccTm7a8qCpQ8SU"; 
// Get from: https://console.cloud.google.com/
// Enable "Safe Browsing API" and create an API Key

// Cache for threat intelligence results (to reduce API calls)
const threatCache = new Map();
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

// ===== FAVICON WHITELIST AUTO-SEEDING =====

function waitForTabComplete(tabId, timeout = 20000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      chrome.tabs.onUpdated.removeListener(onUpdated);
      reject(new Error("Tab load timeout"));
    }, timeout);

    function onUpdated(updatedTabId, info) {
      if (updatedTabId === tabId && info.status === "complete") {
        clearTimeout(timer);
        chrome.tabs.onUpdated.removeListener(onUpdated);
        resolve();
      }
    }
    chrome.tabs.onUpdated.addListener(onUpdated);
  });
}

function toHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function computeSha256(arrayBuffer) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", arrayBuffer);
  return toHex(hashBuffer);
}

async function getFaviconHashForTab(tabId) {
  try {
    const tab = await chrome.tabs.get(tabId);
    
    if (!tab.favIconUrl) {
      return { error: "No favicon URL" };
    }

    const response = await fetch(tab.favIconUrl);
    if (!response.ok) {
      throw new Error(`Fetch failed: ${response.status}`);
    }

    const arrayBuffer = await response.arrayBuffer();
    const sha256 = await computeSha256(arrayBuffer);

    return {
      faviconUrl: tab.favIconUrl,
      sha256: sha256
    };
  } catch (err) {
    return { error: String(err) };
  }
}

async function autoSeedFaviconWhitelist(domainItems) {
  const results = {};

  for (const item of domainItems) {
    const { domain, label } = item;
    
    try {
      console.log(`📍 Processing ${domain} (${label})...`);
      
      const tab = await chrome.tabs.create({ url: domain, active: false });
      if (!tab || !tab.id) continue;

      const tabId = tab.id;

      try {
        await waitForTabComplete(tabId, 25000);
        await new Promise(resolve => setTimeout(resolve, 2000)); // Wait for favicon
      } catch (err) {
        console.warn(`⏱️ Timeout for ${domain}`);
      }

      const result = await getFaviconHashForTab(tabId);

      if (result.sha256) {
        results[result.sha256] = label;
        console.log(`✅ ${domain} added to whitelist`);
      } else {
        console.warn(`❌ Failed for ${domain}: ${result.error}`);
      }

      await chrome.tabs.remove(tabId);
      await new Promise(resolve => setTimeout(resolve, 1000));
    } catch (err) {
      console.error(`❌ Error processing ${domain}:`, err);
    }
  }

  // Save to storage
  const existing = await chrome.storage.local.get(["faviconHashWhitelist"]);
  const existingMap = existing?.faviconHashWhitelist || {};
  const merged = { ...existingMap, ...results };

  await chrome.storage.local.set({ faviconHashWhitelist: merged });

  console.log(`✅ Favicon whitelist auto-seeded! Total entries: ${Object.keys(merged).length}`);
}

// ===== STRIDE ALERT - THREAT INTELLIGENCE =====

async function checkGoogleSafeBrowsing(url) {
  console.log("🔍 Checking Google Safe Browsing for:", url);
  
  try {
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_API_KEY}`;
    
    const requestBody = {
      client: {
        clientId: "SecureSight",
        clientVersion: "1.0.0"
      },
      threatInfo: {
        threatTypes: [
          "MALWARE", 
          "SOCIAL_ENGINEERING", 
          "UNWANTED_SOFTWARE", 
          "POTENTIALLY_HARMFUL_APPLICATION"
        ],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url: url }]
      }
    };

    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
      throw new Error(`GSB API error: ${response.status}`);
    }

    const data = await response.json();

    if (data.matches && data.matches.length > 0) {
      const match = data.matches[0];
      console.log("⚠️ Threat detected by Google Safe Browsing:", match.threatType);
      
      return {
        safe: false,
        threatType: match.threatType,
        source: "Google Safe Browsing",
        details: getThreatDescription(match.threatType)
      };
    }

    console.log("✅ No threats found by Google Safe Browsing");
    return {
      safe: true,
      threatType: null,
      source: "Google Safe Browsing",
      details: "No threats detected"
    };

  } catch (error) {
    console.error("❌ Google Safe Browsing check failed:", error);
    return {
      safe: null,
      threatType: null,
      source: "Google Safe Browsing",
      details: "Unable to verify site safety (API error)",
      error: error.message
    };
  }
}

async function checkThreatIntelligence(url) {
  console.log("🛡️ Starting STRIDE Alert threat check for:", url);

  // Check cache first
  const cachedResult = threatCache.get(url);
  if (cachedResult && (Date.now() - cachedResult.timestamp) < CACHE_DURATION) {
    console.log("✓ Using cached threat result");
    return cachedResult.data;
  }

  // Check Google Safe Browsing
  const result = await checkGoogleSafeBrowsing(url);

  // Cache the result
  threatCache.set(url, {
    data: result,
    timestamp: Date.now()
  });

  console.log("✓ Threat check complete:", result);
  return result;
}

function getThreatDescription(threatType) {
  const descriptions = {
    "MALWARE": "This site may host malware or harmful software",
    "SOCIAL_ENGINEERING": "This site has been reported as a phishing attempt",
    "UNWANTED_SOFTWARE": "This site may distribute unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "This site may contain potentially harmful applications"
  };
  return descriptions[threatType] || "Potential security threat detected";
}

// ===== WHOIS LOOKUP =====

async function fetchWhois(domain) {
  const apiKey = "at_Kzah5rJndT0qp9QX45yTnA9ef22Sc";
  const url = `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${apiKey}&domainName=${domain}&outputFormat=JSON`;
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Network error: ${res.status}`);
    const data = await res.json();
    const createdDate =
      data.WhoisRecord &&
      (data.WhoisRecord.createdDate ||
        (data.WhoisRecord.registryData &&
          data.WhoisRecord.registryData.createdDate));
    return createdDate || null;
  } catch (err) {
    console.error("WHOIS lookup failed:", err);
    return null;
  }
}

// ===== SSL/TLS CERTIFICATE CHECK =====

async function checkSSLCertificate(domain) {
  console.log("=== Starting SSL check for:", domain);
  const cleanDomain = domain.replace(/^www\./, "").split(":")[0];
  console.log("Clean domain:", cleanDomain);

  try {
    const url = `https://crt.sh/?q=${encodeURIComponent(cleanDomain)}&output=json`;
    console.log("Fetching:", url);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeoutId);

    console.log("Response status:", response.status);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const certificates = await response.json();
    console.log("Certificates found:", certificates.length);

    if (!Array.isArray(certificates) || certificates.length === 0) {
      return await checkSSLViaConnectivity(cleanDomain);
    }

    const certsWithDates = certificates.filter(cert => cert.not_before && cert.not_after);
    console.log("Certificates with dates:", certsWithDates.length);

    if (certsWithDates.length === 0) {
      return await checkSSLViaConnectivity(cleanDomain);
    }

    const sortedCerts = certsWithDates.sort((a, b) => {
      return new Date(b.not_after) - new Date(a.not_after);
    });

    const now = new Date();
    let validCert = null;
    
    for (const cert of sortedCerts) {
      const notBefore = new Date(cert.not_before);
      const notAfter = new Date(cert.not_after);
      
      if (now >= notBefore && now <= notAfter) {
        validCert = cert;
        console.log("✓ Found currently valid cert:", cert.id);
        break;
      }
    }

    if (!validCert) {
      console.log("No currently valid certificate found");
      return await checkSSLViaConnectivity(cleanDomain);
    }

    const notBefore = new Date(validCert.not_before);
    const notAfter = new Date(validCert.not_after);
    const isValid = now >= notBefore && now <= notAfter;

    let issuer = "Unknown";
    if (validCert.issuer_name) {
      const orgMatch = validCert.issuer_name.match(/O=([^,]+)/);
      if (orgMatch) {
        issuer = orgMatch[1].trim();
      } else {
        const cnMatch = validCert.issuer_name.match(/CN=([^,]+)/);
        if (cnMatch) {
          issuer = cnMatch[1].trim();
        } else {
          issuer = validCert.issuer_name.substring(0, 50);
        }
      }
    }

    const result = {
      valid: isValid,
      grade: "N/A",
      issuer: issuer,
      validFrom: notBefore.toISOString(),
      validTill: notAfter.toISOString(),
      commonName: validCert.common_name || validCert.name_value,
    };
    console.log("✓ SSL check result:", result);
    return result;
  } catch (error) {
    console.error("crt.sh failed:", error);
    return await checkSSLViaConnectivity(cleanDomain);
  }
}

async function checkSSLViaConnectivity(domain) {
  try {
    console.log("Testing HTTPS connectivity for:", domain);
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(`https://${domain}/favicon.ico`, {
      method: "HEAD",
      mode: "no-cors",
      signal: controller.signal,
    });

    clearTimeout(timeoutId);
    console.log("✓ HTTPS connection successful");

    return {
      valid: true,
      grade: "N/A",
      issuer: "HTTPS Connection Verified",
      validFrom: null,
      validTill: null,
    };
  } catch (error) {
    console.error("HTTPS connectivity test failed:", error);
    return {
      valid: false,
      grade: "N/A",
      issuer: "HTTPS Connection Failed",
      validFrom: null,
      validTill: null,
      error: error.message,
    };
  }
}

// ===== MESSAGE HANDLERS =====

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "whois_lookup") {
    fetchWhois(msg.domain)
      .then((date) => sendResponse({ createdDate: date }))
      .catch(() => sendResponse({ createdDate: null }));
    return true;
  }

  if (msg.type === "threat_check") {
    console.log("Received threat check request for:", msg.url);
    checkThreatIntelligence(msg.url)
      .then((result) => {
        console.log("Sending threat result:", result);
        sendResponse(result);
      })
      .catch((error) => {
        console.error("❌ Threat check error:", error);
        sendResponse({
          safe: null,
          threatType: null,
          source: "Error",
          details: "Threat check failed",
          error: error.message
        });
      });
    return true;
  }

  if (msg.type === "ssl_check") {
    console.log("Received SSL check request for:", msg.domain);
    checkSSLCertificate(msg.domain)
      .then((result) => {
        console.log("Sending SSL result:", result);
        sendResponse(result);
      })
      .catch((error) => {
        console.error("❌ SSL check error:", error);
        sendResponse({
          valid: null,
          grade: "N/A",
          issuer: "Check failed",
          validFrom: null,
          validTill: null,
          error: error.message,
        });
      });
    return true;
  }
});