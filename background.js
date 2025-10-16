// Runs once when the extension is installed
chrome.runtime.onInstalled.addListener(() => {
  console.log("SecureSight extension installed.");
});

// WHOIS Lookup Handler (using WhoisXML API key)
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

// Threat intelligence placeholder
async function threatIntelLookup(domain) {
  // Need to Replace
  return { flagged: null, source: null, details: null };
}

// SSL/TLS Certificate Check
async function checkSSLCertificate(domain) {
  console.log("=== Starting SSL check for:", domain);

  // Clean the domain
  const cleanDomain = domain.replace(/^www\./, "").split(":")[0];
  console.log("Clean domain:", cleanDomain);

  try {
    // Method 1: Try crt.sh (most reliable for certificate info)
    const url = `https://crt.sh/?q=${encodeURIComponent(
      cleanDomain
    )}&output=json`;
    console.log("Fetching:", url);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeoutId);

    console.log("Response status:", response.status);
    console.log("Response OK:", response.ok);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const certificates = await response.json();
    console.log("Certificates found:", certificates.length);

    if (!Array.isArray(certificates) || certificates.length === 0) {
      // Fallback to connectivity test
      return await checkSSLViaConnectivity(cleanDomain);
    }

    // Sort by entry timestamp
    const sortedCerts = certificates.sort((a, b) => {
      const dateA = new Date(a.entry_timestamp);
      const dateB = new Date(b.entry_timestamp);
      return dateB - dateA;
    });

    console.log("Most recent cert ID:", sortedCerts[0].id);

    // Find the first certificate with valid dates
    let validCert = null;
    for (const cert of sortedCerts) {
      if (cert.not_before && cert.not_after) {
        validCert = cert;
        break;
      }
    }

    if (!validCert) {
      console.log("No certificate with valid dates found");
      return await checkSSLViaConnectivity(cleanDomain);
    }

    // Parse dates
    const notBefore = new Date(validCert.not_before);
    const notAfter = new Date(validCert.not_after);
    const now = new Date();

    console.log("Not Before:", notBefore);
    console.log("Not After:", notAfter);
    console.log("Now:", now);

    // Check if certificate is currently valid
    const isValid = now >= notBefore && now <= notAfter;
    console.log("Certificate valid:", isValid);

    // Extract issuer organization
    let issuer = "Unknown";
    if (validCert.issuer_name) {
      // Try to extract O= (Organization)
      const orgMatch = validCert.issuer_name.match(/O=([^,]+)/);
      if (orgMatch) {
        issuer = orgMatch[1].trim();
      } else {
        // Try CN= (Common Name) as fallback
        const cnMatch = validCert.issuer_name.match(/CN=([^,]+)/);
        if (cnMatch) {
          issuer = cnMatch[1].trim();
        } else {
          // Just take first 50 chars
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
    console.log("Falling back to connectivity test...");

    // Fallback: Test HTTPS connectivity
    return await checkSSLViaConnectivity(cleanDomain);
  }
}

// Fallback method: Test if HTTPS connection works
async function checkSSLViaConnectivity(domain) {
  try {
    console.log("Testing HTTPS connectivity for:", domain);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    // Try to connect via HTTPS
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

// Handle messages from popup or content scripts
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "whois_lookup") {
    fetchWhois(msg.domain)
      .then((date) => sendResponse({ createdDate: date }))
      .catch(() => sendResponse({ createdDate: null }));
    return true;
  }

  if (msg.type === "threat_lookup") {
    threatIntelLookup(msg.domain)
      .then((result) => sendResponse(result))
      .catch(() =>
        sendResponse({ flagged: null, source: null, details: null })
      );
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
