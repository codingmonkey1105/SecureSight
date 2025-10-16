// background.js
// Runs once when the extension is installed
chrome.runtime.onInstalled.addListener(() => {
  console.log("SecureSight extension installed.");
});

// WHOIS Lookup Handler (using WhoisXML API key you had)
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


// --- Favicon Fetch Proxy (fixes CORS issue) ---
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "fetchFavicon") {
    console.log("Background: fetching favicon from", msg.url);

    fetch(msg.url, { mode: "no-cors" })
      .then(async (r) => {
        try {
          // Convert to blob (even if opaque)
          const blob = await r.blob();

          // Read as ArrayBuffer
          const reader = new FileReader();
          reader.onloadend = () => {
            const buffer = reader.result;
            sendResponse({ buffer });
          };
          reader.onerror = (err) => {
            console.error("FileReader failed:", err);
            sendResponse({ error: err.toString() });
          };
          reader.readAsArrayBuffer(blob);
        } catch (err) {
          console.error("Blob conversion failed:", err);
          sendResponse({ error: err.toString() });
        }
      })
      .catch((err) => {
        console.error("Background favicon fetch failed:", err);
        sendResponse({ error: err.toString() });
      });

    return true; // keep message channel open
  }
});

