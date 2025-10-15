const scanButton = document.getElementById("scanButton");
const tableEl = document.getElementById("resultTable");
const domainAgeEl = document.getElementById("domainAgeResult");

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

  // ✅ improved logic for complex fields
  const faviconKnown = f.matchedName ? true : f.sha256 ? false : null; // null = unknown
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

// On popup open → load last results + domain age
(async function init() {
  const stored = await chrome.storage.local.get(["lastScan"]);
  if (stored.lastScan) renderTable(stored.lastScan);

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.url) {
    const domain = new URL(tab.url).hostname;
    chrome.runtime.sendMessage({ type: "whois_lookup", domain }, (resp) =>
      renderDomainAge(resp?.createdDate)
    );
  }
})();
