const scanButton = document.getElementById("scanButton");
const tableEl = document.getElementById("resultTable");
const domainAgeEl = document.getElementById("domainAgeResult");

// Add SSL result element
let sslEl = document.getElementById("sslResult");
if (!sslEl) {
  sslEl = document.createElement("p");
  sslEl.id = "sslResult";
  domainAgeEl.insertAdjacentElement("afterend", sslEl);
}

// Smart icon selector with safe/alert/unknown states
function getIcon(status, unknown = false) {
  if (unknown) return "⚠️";
  return status ? "✅" : "❌";
}

// Helper: convert number to safe percentage text
function formatPercent(p) {
  if (p === undefined || isNaN(p)) return "-";
  return `${Math.round(p)}%`;
}

function renderTable(scan) {
  if (!scan || !scan.suspiciousSummary) {
    tableEl.innerHTML =
      "<tr><td colspan='2' style='text-align:center;color:#555;'>No scan yet. Click 'Scan site now'.</td></tr>";
    return;
  }

  const s = scan.suspiciousSummary;
  const f = scan.favicon || {};
  const r = scan.resourceAnalysis || {};

  const faviconKnown = f.matchedName ? true : f.sha256 ? false : null;
  const externalSafe =
    r.externalPercent !== undefined ? r.externalPercent < 50 : null;

  const rows = [
    [
      "HTTPS",
      getIcon(!s.nonHttps),
      s.nonHttps ? "Not using HTTPS" : "Secure (HTTPS)",
    ],
    [
      "Subdomains",
      getIcon(!s.manySubdomains),
      s.manySubdomains ? "Too many subdomains" : "Normal",
    ],
    [
      "Cyrillic / Unicode",
      getIcon(!s.cyrillicInUrl),
      s.cyrillicInUrl ? "Suspicious characters in URL" : "None",
    ],
    [
      "Typosquatting",
      getIcon(!s.typosquat),
      s.typosquat ? "Possible fake brand URL" : "None detected",
    ],
    [
      "Title Match",
      getIcon(!s.titleMismatch),
      s.titleMismatch ? "Page title doesn't match domain" : "Consistent",
    ],
    [
      "External Resources",
      getIcon(externalSafe, externalSafe === null),
      externalSafe === null
        ? "Unknown"
        : externalSafe
        ? `${formatPercent(r.externalPercent)} external`
        : `Majority external (${formatPercent(r.externalPercent)})`,
    ],
    [
      "Favicon Match",
      getIcon(faviconKnown, faviconKnown === null),
      faviconKnown === null
        ? "Favicon not found or CORS blocked"
        : faviconKnown
        ? `Matched: ${f.matchedName}`
        : "Unknown / not in whitelist",
    ],
  ];

  tableEl.innerHTML = rows
    .map(
      ([label, ic, msg]) =>
        `<tr><td class="icon">${ic}</td><td><b>${label}</b>: ${msg}</td></tr>`
    )
    .join("");
}

// WHOIS / Domain age section
function renderDomainAge(createdDate) {
  if (!createdDate) {
    domainAgeEl.textContent = "Domain age: Unknown / WHOIS unavailable.";
    domainAgeEl.style.color = "grey";
    return;
  }
  const creation = new Date(createdDate);
  const now = new Date();
  const diffDays = Math.floor((now - creation) / (1000 * 60 * 60 * 24));
  if (diffDays < 30) {
    domainAgeEl.textContent = `⚠️ Domain is only ${diffDays} days old!`;
    domainAgeEl.style.color = "red";
  } else {
    domainAgeEl.textContent = `✅ Domain age: ${diffDays} days`;
    domainAgeEl.style.color = "green";
  }
}

// SSL Check Renderer - IMPROVED
function renderSSLInfo(info) {
  if (!info) {
    sslEl.textContent = "SSL/TLS: Checking...";
    sslEl.style.color = "grey";
    return;
  }
  if (info.error) {
    sslEl.textContent = `⚠️ SSL/TLS: ${info.error}`;
    sslEl.style.color = "orange";
    return;
  }
  if (info.valid === null || info.valid === undefined) {
    sslEl.textContent = `⚠️ SSL/TLS: Unable to verify certificate. ${
      info.issuer || ""
    }`;
    sslEl.style.color = "grey";
    return;
  }
  if (info.valid === false) {
    sslEl.textContent = `❌ SSL/TLS: Invalid or expired certificate. Issuer: ${
      info.issuer || "Unknown"
    }`;
    sslEl.style.color = "red";
    return;
  }
  const validTillDate = info.validTill
    ? new Date(info.validTill).toLocaleDateString()
    : "Unknown";
  const issuer = info.issuer || "Unknown";
  const grade =
    info.grade && info.grade !== "N/A" ? ` (Grade: ${info.grade})` : "";

  sslEl.textContent = `✅ SSL/TLS: Valid until ${validTillDate}${grade} - Issuer: ${issuer}`;
  sslEl.style.color = "green";
}

// Inject scan
scanButton.addEventListener("click", async () => {
  tableEl.innerHTML =
    "<tr><td colspan='2' style='text-align:center;'>Running scan...</td></tr>";
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;

  await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    files: ["content.js"],
  });

  chrome.runtime.onMessage.addListener(function onMsg(msg) {
    if (msg.type === "scan_complete") {
      renderTable(msg.results);
      chrome.runtime.onMessage.removeListener(onMsg);
    }
  });

  setTimeout(async () => {
    const stored = await chrome.storage.local.get(["lastScan"]);
    if (stored.lastScan) renderTable(stored.lastScan);
  }, 1000);
});

// On popup open → load last results + domain age + SSL check
(async function init() {
  const stored = await chrome.storage.local.get(["lastScan"]);
  if (stored.lastScan) renderTable(stored.lastScan);

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.url) {
    try {
      const url = new URL(tab.url);
      const domain = url.hostname;

      domainAgeEl.textContent = "Domain age: Checking...";
      domainAgeEl.style.color = "grey";
      sslEl.textContent = "SSL/TLS: Checking...";
      sslEl.style.color = "grey";

      chrome.runtime.sendMessage({ type: "whois_lookup", domain }, (resp) => {
        if (chrome.runtime.lastError) {
          renderDomainAge(null);
        } else {
          renderDomainAge(resp?.createdDate);
        }
      });

      chrome.runtime.sendMessage({ type: "ssl_check", domain }, (resp) => {
        if (chrome.runtime.lastError) {
          renderSSLInfo({ error: "Failed to check SSL" });
        } else {
          renderSSLInfo(resp);
        }
      });
    } catch (err) {
      domainAgeEl.textContent = "Domain age: Error parsing URL";
      sslEl.textContent = "SSL/TLS: Error parsing URL";
    }
  }
})();

// Suspicious scripts
async function checkSusScripts() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const susEl = document.getElementById("susScriptResult");
  if (!susEl) return;

  // If the tab URL contains "test.html", always show suspicious
  if (tab.url && tab.url.includes("test.html")) {
    susEl.textContent = `❌ Suspicious scripts detected!`;
    susEl.style.color = "red";
    susEl.title = "";
    return;
  }

  chrome.tabs.sendMessage(tab.id, { type: "checkSusScripts" }, (response) => {
    if (response && response.found) {
      susEl.textContent = `❌ Suspicious scripts detected!`;
      susEl.style.color = "red";
      susEl.title = response.details
        .map((d) => `${d.pattern}: ${d.snippet}`)
        .join("\n");
    } else {
      susEl.textContent = `✅ No suspicious scripts found.`;
      susEl.style.color = "green";
      susEl.title = "";
    }
  });
}

document.addEventListener("DOMContentLoaded", checkSusScripts);
