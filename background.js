// background.js - Complete version with security logging and threat mitigations
importScripts('config.js');
importScripts('storage-integrity.js');
importScripts('secure-logger.js');

const WHOIS_API_KEY = API_KEYS.WHOIS_XML_API;
const GSB_API_KEY = API_KEYS.GOOGLE_SAFE_BROWSING;

// Initialize security managers
const storageIntegrity = new StorageIntegrityManager();
const secureLogger = new SecureLogger();

// Trusted API endpoints for validation (STRIDE: Spoofing mitigation)
const TRUSTED_API_ENDPOINTS = {
  safeBrowsing: {
    hostname: 'safebrowsing.googleapis.com',
    path: '/v4/threatMatches:find'
  },
  whois: {
    hostname: 'www.whoisxmlapi.com',
    path: '/whoisserver/WhoisService'
  },
  ssl: {
    hostname: 'crt.sh',
    path: '/'
  }
};

// Initialize extension on startup
(async function initializeExtension() {
  try {
    await storageIntegrity.initialize();
    await secureLogger.initialize();
    
    await secureLogger.log('EXTENSION_START', {
      version: chrome.runtime.getManifest().version,
      timestamp: Date.now(),
      browser: navigator.userAgent
    }, 'INFO');
    
    console.log('✅ SecureSight security systems initialized');
  } catch (error) {
    console.error('❌ Failed to initialize security systems:', error);
  }
})();

// Runs once when the extension is installed
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log("SecureSight extension installed.");
  
  await secureLogger.log('EXTENSION_INSTALLED', {
    reason: details.reason,
    previousVersion: details.previousVersion,
    currentVersion: chrome.runtime.getManifest().version
  }, 'INFO');
  
  // Only seed on fresh install or update
  if (details.reason === 'install' || details.reason === 'update') {
    console.log("🔄 Auto-seeding favicon whitelist...");
    
    await secureLogger.log('WHITELIST_SEED_START', {
      reason: details.reason
    }, 'INFO');
    
    // Define your trusted domains
    const trustedDomains = [
      { domain: "https://www.amazon.com", label: "Amazon" },
      { domain: "https://www.apple.com", label: "Apple" }
    ];
    
    // Auto-seed the whitelist
    await autoSeedFaviconWhitelist(trustedDomains);
  }
});

// Cache for threat intelligence results (to reduce API calls)
const threatCache = new Map();
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

// ===== API ENDPOINT VALIDATION (STRIDE: Spoofing Mitigation) =====
function validateAPIEndpoint(url, apiType) {
  const urlObj = new URL(url);
  const trusted = TRUSTED_API_ENDPOINTS[apiType];
  
  if (!trusted) {
    throw new Error(`Unknown API type: ${apiType}`);
  }
  
  // Must use HTTPS
  if (urlObj.protocol !== 'https:') {
    secureLogger.log('SECURITY_VIOLATION', {
      event: 'non_https_api_call',
      url: url,
      apiType: apiType
    }, 'CRITICAL');
    throw new Error(`${apiType} API must use HTTPS`);
  }
  
  // Verify hostname matches expected
  if (urlObj.hostname !== trusted.hostname) {
    secureLogger.log('SECURITY_VIOLATION', {
      event: 'untrusted_api_hostname',
      expected: trusted.hostname,
      actual: urlObj.hostname,
      apiType: apiType
    }, 'CRITICAL');
    throw new Error(`Untrusted ${apiType} API hostname: ${urlObj.hostname}`);
  }
  
  // Verify path starts with expected path
  if (!urlObj.pathname.startsWith(trusted.path)) {
    secureLogger.log('SECURITY_VIOLATION', {
      event: 'unexpected_api_path',
      expected: trusted.path,
      actual: urlObj.pathname,
      apiType: apiType
    }, 'WARN');
    throw new Error(`Unexpected ${apiType} API path: ${urlObj.pathname}`);
  }
  
  return true;
}

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
  
  await secureLogger.log('WHITELIST_SEED_START', {
    domainCount: domainItems.length,
    domains: domainItems.map(d => d.domain)
  }, 'INFO');

  for (const item of domainItems) {
    const { domain, label } = item;
    
    try {
      console.log(`📍 Processing ${domain} (${label})...`);
      
      await secureLogger.log('FAVICON_FETCH_START', {
        domain: domain,
        label: label
      }, 'INFO');
      
      const tab = await chrome.tabs.create({ url: domain, active: false });
      if (!tab || !tab.id) {
        await secureLogger.log('FAVICON_FETCH_FAILED', {
          domain: domain,
          reason: 'tab_creation_failed'
        }, 'WARN');
        continue;
      }

      const tabId = tab.id;

      try {
        await waitForTabComplete(tabId, 25000);
        await new Promise(resolve => setTimeout(resolve, 2000)); // Wait for favicon
      } catch (err) {
        console.warn(`⏱️ Timeout for ${domain}`);
        await secureLogger.log('FAVICON_FETCH_TIMEOUT', {
          domain: domain,
          error: err.message
        }, 'WARN');
      }

      const result = await getFaviconHashForTab(tabId);

      if (result.sha256) {
        results[result.sha256] = label;
        console.log(`✅ ${domain} added to whitelist`);
        
        await secureLogger.log('FAVICON_FETCH_SUCCESS', {
          domain: domain,
          label: label,
          hash: result.sha256
        }, 'INFO');
      } else {
        console.warn(`❌ Failed for ${domain}: ${result.error}`);
        await secureLogger.log('FAVICON_FETCH_FAILED', {
          domain: domain,
          error: result.error
        }, 'WARN');
      }

      await chrome.tabs.remove(tabId);
      await new Promise(resolve => setTimeout(resolve, 1000));
    } catch (err) {
      console.error(`❌ Error processing ${domain}:`, err);
      await secureLogger.log('FAVICON_FETCH_ERROR', {
        domain: domain,
        error: err.message,
        stack: err.stack
      }, 'ERROR');
    }
  }

  // Save to storage with integrity protection
  try {
    const existing = await storageIntegrity.loadWithIntegrity('faviconHashWhitelist');
    const existingMap = existing || {};
    const merged = { ...existingMap, ...results };

    await storageIntegrity.saveWithIntegrity('faviconHashWhitelist', merged);

    await secureLogger.log('WHITELIST_SEED_COMPLETE', {
      newEntries: Object.keys(results).length,
      totalEntries: Object.keys(merged).length
    }, 'INFO');

    console.log(`✅ Favicon whitelist auto-seeded! Total entries: ${Object.keys(merged).length}`);
  } catch (err) {
    await secureLogger.log('WHITELIST_SAVE_FAILED', {
      error: err.message
    }, 'ERROR');
  }
}

// ===== STRIDE ALERT - THREAT INTELLIGENCE =====

async function checkGoogleSafeBrowsing(url) {
  console.log("🔍 Checking Google Safe Browsing for:", url);
  
  await secureLogger.log('API_CALL_START', {
    api: 'Google Safe Browsing',
    url: url,
    timestamp: Date.now()
  }, 'INFO');
  
  try {
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GSB_API_KEY}`;
    
    // Validate API endpoint (STRIDE: Spoofing mitigation)
    try {
      validateAPIEndpoint(endpoint, 'safeBrowsing');
    } catch (error) {
      await secureLogger.log('API_VALIDATION_FAILED', {
        api: 'Google Safe Browsing',
        error: error.message
      }, 'CRITICAL');
      
      return {
        safe: null,
        threatType: null,
        source: "Google Safe Browsing",
        details: "API endpoint validation failed",
        error: error.message
      };
    }
    
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

    // Add timeout to prevent hanging (STRIDE: DoS mitigation)
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(endpoint, {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
        "X-Request-Source": "SecureSight-Extension"
      },
      body: JSON.stringify(requestBody),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      await secureLogger.log('API_CALL_FAILED', {
        api: 'Google Safe Browsing',
        status: response.status,
        statusText: response.statusText,
        url: url
      }, 'ERROR');
      
      throw new Error(`GSB API error: ${response.status}`);
    }

    const data = await response.json();
    
    // Validate response structure (STRIDE: Tampering mitigation)
    if (typeof data !== 'object') {
      await secureLogger.log('API_RESPONSE_INVALID', {
        api: 'Google Safe Browsing',
        reason: 'response_not_object'
      }, 'ERROR');
      throw new Error('Invalid API response format');
    }

    if (data.matches && data.matches.length > 0) {
      const match = data.matches[0];
      
      await secureLogger.log('THREAT_DETECTED', {
        api: 'Google Safe Browsing',
        url: url,
        threatType: match.threatType,
        platformType: match.platformType,
        threatEntryType: match.threatEntryType
      }, 'WARN');
      
      console.log("⚠️ Threat detected by Google Safe Browsing:", match.threatType);
      
      return {
        safe: false,
        threatType: match.threatType,
        source: "Google Safe Browsing",
        details: getThreatDescription(match.threatType)
      };
    }

    await secureLogger.log('API_CALL_SUCCESS', {
      api: 'Google Safe Browsing',
      url: url,
      result: 'safe',
      timestamp: Date.now()
    }, 'INFO');
    
    console.log("✅ No threats found by Google Safe Browsing");
    return {
      safe: true,
      threatType: null,
      source: "Google Safe Browsing",
      details: "No threats detected"
    };

  } catch (error) {
    await secureLogger.log('API_CALL_ERROR', {
      api: 'Google Safe Browsing',
      url: url,
      error: error.message,
      errorName: error.name,
      stack: error.stack
    }, 'ERROR');
    
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
  
  await secureLogger.log('THREAT_CHECK_START', {
    url: url
  }, 'INFO');

  // Check cache first (reduce API calls)
  const cachedResult = threatCache.get(url);
  if (cachedResult && (Date.now() - cachedResult.timestamp) < CACHE_DURATION) {
    console.log("✓ Using cached threat result");
    
    await secureLogger.log('THREAT_CHECK_CACHE_HIT', {
      url: url,
      cacheAge: Date.now() - cachedResult.timestamp
    }, 'INFO');
    
    return cachedResult.data;
  }

  // Check Google Safe Browsing
  const result = await checkGoogleSafeBrowsing(url);

  // Cache the result
  threatCache.set(url, {
    data: result,
    timestamp: Date.now()
  });
  
  // Clean old cache entries (prevent memory bloat)
  if (threatCache.size > 1000) {
    const oldestKey = threatCache.keys().next().value;
    threatCache.delete(oldestKey);
  }

  await secureLogger.log('THREAT_CHECK_COMPLETE', {
    url: url,
    safe: result.safe,
    threatType: result.threatType,
    cached: true
  }, 'INFO');

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

function isValidDomain(domain) {
  // Basic domain validation (STRIDE: Input validation)
  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
  return domainRegex.test(domain);
}

async function fetchWhois(domain) {
  // Validate domain format
  if (!isValidDomain(domain)) {
    await secureLogger.log('WHOIS_INVALID_DOMAIN', {
      domain: domain
    }, 'WARN');
    return null;
  }
  
  await secureLogger.log('WHOIS_LOOKUP_START', {
    domain: domain,
    timestamp: Date.now()
  }, 'INFO');
  
  const url = `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${WHOIS_API_KEY}&domainName=${domain}&outputFormat=JSON`;
  
  // Validate API endpoint
  try {
    validateAPIEndpoint(url, 'whois');
  } catch (error) {
    await secureLogger.log('API_VALIDATION_FAILED', {
      api: 'WHOIS',
      error: error.message
    }, 'ERROR');
    return null;
  }
  
  try {
    // Add timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    
    const res = await fetch(url, { signal: controller.signal });
    clearTimeout(timeoutId);
    
    if (!res.ok) {
      await secureLogger.log('WHOIS_LOOKUP_FAILED', {
        domain: domain,
        status: res.status,
        statusText: res.statusText
      }, 'WARN');
      throw new Error(`Network error: ${res.status}`);
    }
    
    const data = await res.json();
    const createdDate =
      data.WhoisRecord &&
      (data.WhoisRecord.createdDate ||
        (data.WhoisRecord.registryData &&
          data.WhoisRecord.registryData.createdDate));
    
    await secureLogger.log('WHOIS_LOOKUP_SUCCESS', {
      domain: domain,
      createdDate: createdDate,
      hasData: !!createdDate
    }, 'INFO');
    
    return createdDate || null;
  } catch (err) {
    await secureLogger.log('WHOIS_LOOKUP_ERROR', {
      domain: domain,
      error: err.message,
      errorName: err.name
    }, 'ERROR');
    
    console.error("WHOIS lookup failed:", err);
    return null;
  }
}

// ===== SSL/TLS CERTIFICATE CHECK =====

async function checkSSLCertificate(domain) {
  console.log("=== Starting SSL check for:", domain);
  
  await secureLogger.log('SSL_CHECK_START', {
    domain: domain
  }, 'INFO');
  
  const cleanDomain = domain.replace(/^www\./, "").split(":")[0];
  console.log("Clean domain:", cleanDomain);

  try {
    const url = `https://crt.sh/?q=${encodeURIComponent(cleanDomain)}&output=json`;
    console.log("Fetching:", url);
    
    // Validate endpoint
    try {
      validateAPIEndpoint(url, 'ssl');
    } catch (error) {
      await secureLogger.log('SSL_API_VALIDATION_FAILED', {
        domain: domain,
        error: error.message
      }, 'WARN');
      return await checkSSLViaConnectivity(cleanDomain);
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeoutId);

    console.log("Response status:", response.status);

    if (!response.ok) {
      await secureLogger.log('SSL_CHECK_API_FAILED', {
        domain: domain,
        status: response.status
      }, 'WARN');
      throw new Error(`HTTP ${response.status}`);
    }

    const certificates = await response.json();
    console.log("Certificates found:", certificates.length);

    if (!Array.isArray(certificates) || certificates.length === 0) {
      await secureLogger.log('SSL_CHECK_NO_CERTS', {
        domain: domain
      }, 'INFO');
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
      await secureLogger.log('SSL_CHECK_NO_VALID_CERT', {
        domain: domain,
        certsFound: certificates.length
      }, 'WARN');
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
    
    await secureLogger.log('SSL_CHECK_SUCCESS', {
      domain: domain,
      valid: isValid,
      issuer: issuer,
      validTill: notAfter.toISOString()
    }, 'INFO');
    
    console.log("✓ SSL check result:", result);
    return result;
  } catch (error) {
    await secureLogger.log('SSL_CHECK_ERROR', {
      domain: domain,
      error: error.message
    }, 'ERROR');
    
    console.error("crt.sh failed:", error);
    return await checkSSLViaConnectivity(cleanDomain);
  }
}

async function checkSSLViaConnectivity(domain) {
  try {
    console.log("Testing HTTPS connectivity for:", domain);
    
    await secureLogger.log('SSL_CONNECTIVITY_CHECK', {
      domain: domain,
      method: 'https_test'
    }, 'INFO');
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(`https://${domain}/favicon.ico`, {
      method: "HEAD",
      mode: "no-cors",
      signal: controller.signal,
    });

    clearTimeout(timeoutId);
    console.log("✓ HTTPS connection successful");
    
    await secureLogger.log('SSL_CONNECTIVITY_SUCCESS', {
      domain: domain
    }, 'INFO');

    return {
      valid: true,
      grade: "N/A",
      issuer: "HTTPS Connection Verified",
      validFrom: null,
      validTill: null,
    };
  } catch (error) {
    console.error("HTTPS connectivity test failed:", error);
    
    await secureLogger.log('SSL_CONNECTIVITY_FAILED', {
      domain: domain,
      error: error.message
    }, 'WARN');
    
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

// ===== MESSAGE HANDLERS WITH SECURITY =====

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // CRITICAL: Verify sender is from our extension (STRIDE: Spoofing mitigation)
  if (sender.id !== chrome.runtime.id) {
    secureLogger.log('SECURITY_VIOLATION', {
      event: 'unauthorized_sender',
      senderId: sender.id,
      messageType: msg.type,
      senderUrl: sender.url
    }, 'CRITICAL');
    
    console.error('[SECURITY] Message from unauthorized extension:', sender.id);
    return false; // Reject message
  }
  
  // Log all message handling
  secureLogger.log('MESSAGE_RECEIVED', {
    type: msg.type,
    fromTab: sender.tab ? sender.tab.id : 'popup',
    url: sender.url,
    frameId: sender.frameId
  }, 'DEBUG');
  
  // Verify sender origin for content scripts
  if (msg.type === 'scan_complete') {
    // Must be from a content script (has tab context)
    if (!sender.tab) {
      secureLogger.log('SECURITY_VIOLATION', {
        event: 'invalid_sender_context',
        messageType: msg.type,
        expectedContext: 'content_script',
        actualContext: 'no_tab'
      }, 'WARN');
      
      console.error('[SECURITY] scan_complete message not from content script');
      return false;
    }
    
    // Verify it's from the top frame (not an iframe)
    if (sender.frameId !== 0) {
      secureLogger.log('SECURITY_WARNING', {
        event: 'message_from_iframe',
        frameId: sender.frameId,
        url: sender.url
      }, 'WARN');
      
      console.warn('[SECURITY] Message from iframe - potential security risk');
    }
  }
  
  // Verify sender for popup/background messages
  if (msg.type === 'whois_lookup' || msg.type === 'threat_check' || msg.type === 'ssl_check') {
    // These should come from popup, not content scripts
    if (sender.tab) {
      secureLogger.log('SECURITY_VIOLATION', {
        event: 'api_call_from_content_script',
        messageType: msg.type,
        tabId: sender.tab.id
      }, 'WARN');
      
      console.error('[SECURITY] Background API call from content script - not allowed');
      return false;
    }
  }
  
  // Handle message types
  if (msg.type === "whois_lookup") {
    // Validate domain format (STRIDE: Input validation)
    if (!msg.domain || !isValidDomain(msg.domain)) {
      secureLogger.log('INVALID_INPUT', {
        messageType: 'whois_lookup',
        domain: msg.domain
      }, 'WARN');
      
      console.error('[SECURITY] Invalid domain format:', msg.domain);
      sendResponse({ createdDate: null });
      return false;
    }
    
    fetchWhois(msg.domain)
      .then((date) => {
        sendResponse({ createdDate: date });
      })
      .catch((error) => {
        secureLogger.log('MESSAGE_HANDLER_ERROR', {
          messageType: 'whois_lookup',
          error: error.message
        }, 'ERROR');
        sendResponse({ createdDate: null });
      });
    return true;
  }

  if (msg.type === "threat_check") {
    // Validate URL format
    if (!msg.url || typeof msg.url !== 'string') {
      secureLogger.log('INVALID_INPUT', {
        messageType: 'threat_check',
        url: msg.url
      }, 'WARN');
      
      sendResponse({
        safe: null,
        threatType: null,
        source: "Error",
        details: "Invalid URL format"
      });
      return false;
    }
    
    console.log("Received threat check request for:", msg.url);
    checkThreatIntelligence(msg.url)
      .then((result) => {
        console.log("Sending threat result:", result);
        // STRIDE: Only send plain data, never functions (Tampering mitigation)
        const safeResult = JSON.parse(JSON.stringify(result));
        sendResponse(safeResult);
      })
      .catch((error) => {
        secureLogger.log('THREAT_CHECK_ERROR', {
          url: msg.url,
          error: error.message
        }, 'ERROR');
        
        console.error("❌ Threat check error:", error);
        sendResponse({
          safe: null,
          threatType: null,
          source: "Error",
          details: "Threat check failed",
          error: String(error.message)
        });
      });
    return true;
  }

  if (msg.type === "ssl_check") {
    // Validate domain format
    if (!msg.domain || !isValidDomain(msg.domain)) {
      secureLogger.log('INVALID_INPUT', {
        messageType: 'ssl_check',
        domain: msg.domain
      }, 'WARN');
      
      sendResponse({
        valid: null,
        grade: "N/A",
        issuer: "Invalid domain format",
        validFrom: null,
        validTill: null
      });
      return false;
    }
    
    console.log("Received SSL check request for:", msg.domain);
    checkSSLCertificate(msg.domain)
      .then((result) => {
        console.log("Sending SSL result:", result);
        // STRIDE: Only send plain data (Tampering mitigation)
        const safeResult = JSON.parse(JSON.stringify(result));
        sendResponse(safeResult);
      })
      .catch((error) => {
        secureLogger.log('SSL_CHECK_ERROR', {
          domain: msg.domain,
          error: error.message
        }, 'ERROR');
        
        console.error("❌ SSL check error:", error);
        sendResponse({
          valid: null,
          grade: "N/A",
          issuer: "Check failed",
          validFrom: null,
          validTill: null,
          error: String(error.message),
        });
      });
    return true;
  }
  
  // Unknown message type
  secureLogger.log('UNKNOWN_MESSAGE_TYPE', {
    type: msg.type,
    sender: sender.id,
    fromTab: sender.tab ? sender.tab.id : 'popup'
  }, 'WARN');
  
  console.warn('[SECURITY] Unknown message type:', msg.type);
  return false;
});

// ===== EXTENSION LIFECYCLE EVENTS =====

// Log when extension is suspended (service worker goes idle)
self.addEventListener('suspend', async () => {
  await secureLogger.log('EXTENSION_SUSPEND', {
    timestamp: Date.now(),
    reason: 'service_worker_idle'
  }, 'INFO');
});

// Log errors
self.addEventListener('error', async (error) => {
  await secureLogger.log('EXTENSION_ERROR', {
    message: error.message,
    filename: error.filename,
    lineno: error.lineno,
    colno: error.colno,
    stack: error.error ? error.error.stack : null
  }, 'ERROR');
});

// Log unhandled promise rejections
self.addEventListener('unhandledrejection', async (event) => {
  await secureLogger.log('UNHANDLED_REJECTION', {
    reason: event.reason,
    promise: String(event.promise),
    stack: event.reason ? event.reason.stack : null
  }, 'ERROR');
});

// ===== PERIODIC SECURITY CHECKS =====

// Check log integrity every hour
const LOG_INTEGRITY_CHECK_INTERVAL = 60 * 60 * 1000; // 1 hour

async function performSecurityAudit() {
  try {
    await secureLogger.log('SECURITY_AUDIT_START', {
      timestamp: Date.now()
    }, 'INFO');
    
    // Verify log chain integrity
    const isLogValid = await secureLogger.verifyChainIntegrity();
    
    if (!isLogValid) {
      await secureLogger.log('SECURITY_AUDIT_FAILED', {
        component: 'log_chain',
        issue: 'integrity_violation'
      }, 'CRITICAL');
    }
    
    // Verify storage integrity
    const whitelist = await storageIntegrity.loadWithIntegrity('faviconHashWhitelist');
    const whitelistValid = whitelist !== null;
    
    if (!whitelistValid) {
      await secureLogger.log('SECURITY_AUDIT_FAILED', {
        component: 'storage',
        issue: 'whitelist_integrity_violation'
      }, 'CRITICAL');
    }
    
    await secureLogger.log('SECURITY_AUDIT_COMPLETE', {
      logChainValid: isLogValid,
      storageValid: whitelistValid,
      timestamp: Date.now()
    }, 'INFO');
    
    console.log('✅ Security audit complete');
  } catch (error) {
    await secureLogger.log('SECURITY_AUDIT_ERROR', {
      error: error.message,
      stack: error.stack
    }, 'ERROR');
  }
}

// Schedule periodic security audits
setInterval(performSecurityAudit, LOG_INTEGRITY_CHECK_INTERVAL);

// Perform initial audit after 5 minutes
setTimeout(performSecurityAudit, 5 * 60 * 1000);

// ===== CACHE CLEANUP =====

// Clean threat cache every 10 minutes
setInterval(() => {
  const now = Date.now();
  let cleanedCount = 0;
  
  for (const [url, cached] of threatCache.entries()) {
    if (now - cached.timestamp > CACHE_DURATION) {
      threatCache.delete(url);
      cleanedCount++;
    }
  }
  
  if (cleanedCount > 0) {
    secureLogger.log('CACHE_CLEANUP', {
      entriesRemoved: cleanedCount,
      remainingEntries: threatCache.size
    }, 'DEBUG');
  }
}, 10 * 60 * 1000);

// ===== SECURITY UTILITIES =====

// Sanitize object for sending (remove functions, prevent code injection)
function sanitizeObjectForSending(obj) {
  if (obj === null || obj === undefined) {
    return obj;
  }
  
  // Deep clone and strip functions
  try {
    return JSON.parse(JSON.stringify(obj));
  } catch (error) {
    secureLogger.log('SANITIZATION_ERROR', {
      error: error.message,
      objectType: typeof obj
    }, 'WARN');
    return null;
  }
}

// Rate limiting for API calls (prevent DoS)
class RateLimiter {
  constructor(maxRequests, windowMs) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this.requests = new Map(); // key -> array of timestamps
  }
  
  async checkLimit(key) {
    const now = Date.now();
    
    if (!this.requests.has(key)) {
      this.requests.set(key, []);
    }
    
    const timestamps = this.requests.get(key);
    
    // Remove old timestamps outside the window
    const validTimestamps = timestamps.filter(ts => now - ts < this.windowMs);
    this.requests.set(key, validTimestamps);
    
    if (validTimestamps.length >= this.maxRequests) {
      await secureLogger.log('RATE_LIMIT_EXCEEDED', {
        key: key,
        requestCount: validTimestamps.length,
        maxRequests: this.maxRequests,
        windowMs: this.windowMs
      }, 'WARN');
      
      return false; // Rate limit exceeded
    }
    
    // Add current request
    validTimestamps.push(now);
    this.requests.set(key, validTimestamps);
    
    return true; // Request allowed
  }
  
  reset(key) {
    this.requests.delete(key);
  }
}

// Create rate limiters for different API types
const threatCheckLimiter = new RateLimiter(10, 60000); // 10 requests per minute
const whoisLimiter = new RateLimiter(5, 60000); // 5 requests per minute
const sslCheckLimiter = new RateLimiter(10, 60000); // 10 requests per minute

// Update checkThreatIntelligence with rate limiting
const originalCheckThreatIntelligence = checkThreatIntelligence;
checkThreatIntelligence = async function(url) {
  const allowed = await threatCheckLimiter.checkLimit('threat_check');
  
  if (!allowed) {
    await secureLogger.log('RATE_LIMIT_BLOCKED', {
      api: 'threat_check',
      url: url
    }, 'WARN');
    
    return {
      safe: null,
      threatType: null,
      source: "Rate Limited",
      details: "Too many requests. Please wait.",
      error: "Rate limit exceeded"
    };
  }
  
  return originalCheckThreatIntelligence(url);
};

// Update fetchWhois with rate limiting
const originalFetchWhois = fetchWhois;
fetchWhois = async function(domain) {
  const allowed = await whoisLimiter.checkLimit('whois');
  
  if (!allowed) {
    await secureLogger.log('RATE_LIMIT_BLOCKED', {
      api: 'whois',
      domain: domain
    }, 'WARN');
    
    return null;
  }
  
  return originalFetchWhois(domain);
};

// Update checkSSLCertificate with rate limiting
const originalCheckSSLCertificate = checkSSLCertificate;
checkSSLCertificate = async function(domain) {
  const allowed = await sslCheckLimiter.checkLimit('ssl_check');
  
  if (!allowed) {
    await secureLogger.log('RATE_LIMIT_BLOCKED', {
      api: 'ssl_check',
      domain: domain
    }, 'WARN');
    
    return {
      valid: null,
      grade: "N/A",
      issuer: "Rate Limited",
      validFrom: null,
      validTill: null,
      error: "Too many requests"
    };
  }
  
  return originalCheckSSLCertificate(domain);
};

// ===== EXPORT LOGS API (for debugging/analysis) =====

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'export_logs') {
    // Verify sender
    if (sender.id !== chrome.runtime.id) {
      return false;
    }
    
    secureLogger.log('LOGS_EXPORTED', {
      requestedBy: sender.url,
      timestamp: Date.now()
    }, 'INFO');
    
    const exportData = secureLogger.exportLogs();
    sendResponse(exportData);
    return true;
  }
  
  if (msg.type === 'verify_log_integrity') {
    // Verify sender
    if (sender.id !== chrome.runtime.id) {
      return false;
    }
    
    secureLogger.verifyChainIntegrity().then(isValid => {
      sendResponse({ valid: isValid });
    });
    return true;
  }
  
  if (msg.type === 'get_filtered_logs') {
    // Verify sender
    if (sender.id !== chrome.runtime.id) {
      return false;
    }
    
    const filters = msg.filters || {};
    const logs = secureLogger.getLogs(filters);
    sendResponse({ logs: logs, count: logs.length });
    return true;
  }
});

// ===== EXTENSION INFO =====

console.log(`

   SecureSight Extension - Background Service Worker       
   Version: 1.0                                            
    Security Features:                                      
   ✓ STRIDE Threat Mitigation                              
   ✓ Blockchain-style Tamper-proof Logging                 
   ✓ Storage Integrity Protection (HMAC)                   
   ✓ API Endpoint Validation                               
   ✓ Rate Limiting                                         
   ✓ Input Validation                                      
   ✓ Sender Verification                                  
`);

// Log startup complete
secureLogger.log('BACKGROUND_READY', {
  version: chrome.runtime.getManifest().version,
  features: [
    'threat_intelligence',
    'whois_lookup',
    'ssl_check',
    'favicon_verification',
    'secure_logging',
    'storage_integrity',
    'rate_limiting',
    'input_validation'
  ],
  timestamp: Date.now()
}, 'INFO');
