// background.js
// Runs once when the extension is installed
chrome.runtime.onInstalled.addListener(() => {
  console.log("SecureSight extension installed.");
});

// WHOIS Lookup Handler (using WhoisXML API key you had)
async function fetchWhois(domain) {
  const apiKey = "at_cfNYAdPZ3FA4oYpMgmcs8RK1ZvC9O"; // Replace with your actual WhoisXML API key
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
    console.error("WHOIS lookup failed (whoisxmlapi):", err);
    // If you want, you can add a fallback WHOIS provider here.
    return null;
  }
}

// Optional placeholder for a threat-intel check
async function threatIntelLookup(domain) {
  // Placeholder — plug in PhishTank / Google Safe Browsing / other API here.
  // Return object like: { flagged: false, source: null, details: null }
  return { flagged: null, source: null, details: null };
}

// Message listener
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "whois_lookup") {
    fetchWhois(msg.domain)
      .then((date) => sendResponse({ createdDate: date }))
      .catch(() => sendResponse({ createdDate: null }));
    return true; // Keep channel open for async response
  }

  if (msg.type === "threat_lookup") {
    threatIntelLookup(msg.domain)
      .then((result) => sendResponse(result))
      .catch(() => sendResponse({ flagged: null }));
    return true;
  }

  // allow other messages if needed
});
