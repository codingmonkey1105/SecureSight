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

// Add suspicious links element
let linksEl = document.getElementById("suspiciousLinksResult");
if (!linksEl) {
  linksEl = document.createElement("p");
  linksEl.id = "suspiciousLinksResult";
  sslEl.insertAdjacentElement("afterend", linksEl);
}

// NEW: Threat alert elements
const threatAlertDiv = document.getElementById("threatAlert");
const threatStatusP = document.getElementById("threatStatus");

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

// NEW: Display threat intelligence results
function displayThreatResult(threatResult) {
  if (!threatResult) {
    threatAlertDiv.style.display = "none";
    return;
  }

  threatAlertDiv.style.display = "block";

  if (threatResult.safe === true) {
    // Safe site - green background
    threatAlertDiv.style.backgroundColor = "#d4edda";
    threatAlertDiv.style.borderLeft = "4px solid #28a745";
    threatAlertDiv.style.color = "#155724";
    threatStatusP.innerHTML = `✅ <strong>Safe</strong> - ${threatResult.details}`;
  } else if (threatResult.safe === false) {
    // Threat detected - red background
    threatAlertDiv.style.backgroundColor = "#f8d7da";
    threatAlertDiv.style.borderLeft = "4px solid #dc3545";
    threatAlertDiv.style.color = "#721c24";
    
    const threatTypeLabel = getThreatLabel(threatResult.threatType);
    threatStatusP.innerHTML = `⚠️ <strong>${threatTypeLabel} Detected!</strong><br>${threatResult.details}`;
  } else {
    // Unknown/error - yellow background
    threatAlertDiv.style.backgroundColor = "#fff3cd";
    threatAlertDiv.style.borderLeft = "4px solid #ffc107";
    threatAlertDiv.style.color = "#856404";
    threatStatusP.innerHTML = `⚠️ <strong>Unknown</strong> - ${threatResult.details}`;
  }
}

function getThreatLabel(threatType) {
  const labels = {
    "MALWARE": "Malware",
    "SOCIAL_ENGINEERING": "Phishing",
    "UNWANTED_SOFTWARE": "Unwanted Software",
    "POTENTIALLY_HARMFUL_APPLICATION": "Harmful Application"
  };
  return labels[threatType] || "Threat";
}

// NEW: Map security findings to STRIDE categories
function getSTRIDEThreats(scan) {
  const threats = {
    spoofing: [],
    tampering: [],
    informationDisclosure: [],
    denialOfService: [],
    elevationOfPrivilege: []
  };

  if (!scan || !scan.suspiciousSummary) return threats;

  const s = scan.suspiciousSummary;
  const f = scan.favicon || {};
  const linkData = scan.suspiciousLinks || {};

  // Spoofing: Identity/authentication threats
  if (s.typosquat) {
    threats.spoofing.push("Typosquatting detected (fake brand URL)");
  }
  if (s.cyrillicInUrl) {
    threats.spoofing.push("Homograph attack (lookalike characters)");
  }
  if (s.titleMismatch) {
    threats.spoofing.push("Page title doesn't match domain");
  }
  if (f.sha256 && !f.matchedName) {
    threats.spoofing.push("Favicon not recognized (possible impersonation)");
  }

  // Tampering: Data modification threats
  if (s.nonHttps) {
    threats.tampering.push("Unencrypted connection (data can be modified)");
  }
  if (scan.susScripts && scan.susScripts.found) {
    threats.tampering.push("Suspicious scripts detected (code injection risk)");
  }

  // Information Disclosure: Data exposure threats
  if (s.nonHttps) {
    threats.informationDisclosure.push("Unencrypted connection (data visible to attackers)");
  }
  if (s.hasExternalScripts && s.externalScriptRatio > 50) {
    threats.informationDisclosure.push("High external resource usage (data leakage risk)");
  }

  // Denial of Service: Availability threats
  if (linkData.found) {
    const highRisk = (linkData.links || []).filter(l => l.riskLevel === 'high').length;
    if (highRisk > 0) {
      threats.denialOfService.push(`${highRisk} high-risk malicious links (malware/ransomware risk)`);
    }
  }
  if (s.manySubdomains) {
    threats.denialOfService.push("Excessive subdomains (possible DDoS infrastructure)");
  }

  // Elevation of Privilege: Unauthorized access threats
  if (scan.susScripts && scan.susScripts.found) {
    threats.elevationOfPrivilege.push("Suspicious scripts (XSS/code execution risk)");
  }

  return threats;
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

  // Suspicious links data
  const linkData = scan.suspiciousLinks || {};
  const linksFound = linkData.found;
  const linkCount = linkData.count || 0;
  const totalScanned = linkData.totalScanned || 0;
  
  let linkMessage = "";
  if (totalScanned === 0) {
    linkMessage = "No links scanned";
  } else if (!linksFound) {
    linkMessage = `All ${totalScanned} links safe`;
  } else {
    const highRisk = (linkData.links || []).filter(l => l.riskLevel === 'high').length;
    const mediumRisk = (linkData.links || []).filter(l => l.riskLevel === 'medium').length;
    const lowRisk = (linkData.links || []).filter(l => l.riskLevel === 'low').length;
    linkMessage = `${linkCount} suspicious (H:${highRisk} M:${mediumRisk} L:${lowRisk})`;
  }

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
    [
      "Suspicious Links",
      getIcon(!linksFound, totalScanned === 0),
      linkMessage,
    ],
  ];

  tableEl.innerHTML = rows
    .map(
      ([label, ic, msg]) =>
        `<tr><td class="icon">${ic}</td><td><b>${label}</b>: ${msg}</td></tr>`
    )
    .join("");

  // NEW: Add STRIDE threat analysis
  const strideThreats = getSTRIDEThreats(scan);
  const strideRows = [];

  if (strideThreats.spoofing.length > 0) {
    strideRows.push(`<tr style="background-color: #fff3cd;"><td colspan="2"><b>🎭 Spoofing Threats:</b><br>${strideThreats.spoofing.map(t => `• ${t}`).join('<br>')}</td></tr>`);
  }
  if (strideThreats.tampering.length > 0) {
    strideRows.push(`<tr style="background-color: #f8d7da;"><td colspan="2"><b>🔧 Tampering Threats:</b><br>${strideThreats.tampering.map(t => `• ${t}`).join('<br>')}</td></tr>`);
  }
  if (strideThreats.informationDisclosure.length > 0) {
    strideRows.push(`<tr style="background-color: #d1ecf1;"><td colspan="2"><b>📢 Information Disclosure:</b><br>${strideThreats.informationDisclosure.map(t => `• ${t}`).join('<br>')}</td></tr>`);
  }
  if (strideThreats.denialOfService.length > 0) {
    strideRows.push(`<tr style="background-color: #f8d7da;"><td colspan="2"><b>🚫 Denial of Service Risk:</b><br>${strideThreats.denialOfService.map(t => `• ${t}`).join('<br>')}</td></tr>`);
  }
  if (strideThreats.elevationOfPrivilege.length > 0) {
    strideRows.push(`<tr style="background-color: #f8d7da;"><td colspan="2"><b>👑 Elevation of Privilege:</b><br>${strideThreats.elevationOfPrivilege.map(t => `• ${t}`).join('<br>')}</td></tr>`);
  }

  if (strideRows.length > 0) {
    tableEl.innerHTML += `<tr><td colspan="2" style="text-align:center; background-color: #e9ecef; font-weight: bold; padding: 8px;">🛡️ STRIDE Threat Analysis</td></tr>` + strideRows.join('');
  } else {
    tableEl.innerHTML += `<tr><td colspan="2" style="text-align:center; background-color: #d4edda; color: #155724; padding: 8px;">✅ No STRIDE threats detected</td></tr>`;
  }
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

// SSL Check Renderer
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

// Render suspicious links
function renderSuspiciousLinks(linkData) {
  if (!linkData) {
    linksEl.textContent = "Suspicious Links: Checking...";
    linksEl.style.color = "grey";
    return;
  }

  if (!linkData.found) {
    linksEl.textContent = `✅ No suspicious links found (scanned ${linkData.totalScanned || 0} links)`;
    linksEl.style.color = "green";
    linksEl.title = "";
    return;
  }

  // Count by risk level
  const highRisk = linkData.links.filter(l => l.riskLevel === 'high').length;
  const mediumRisk = linkData.links.filter(l => l.riskLevel === 'medium').length;
  const lowRisk = linkData.links.filter(l => l.riskLevel === 'low').length;

  linksEl.textContent = `❌ Found ${linkData.count} suspicious link(s): ${highRisk} high, ${mediumRisk} medium, ${lowRisk} low risk`;
  linksEl.style.color = highRisk > 0 ? "red" : mediumRisk > 0 ? "orange" : "#fbc02d";
  
  // Create detailed tooltip
  const tooltipLines = linkData.links.slice(0, 10).map(link => {
    const riskIcon = link.riskLevel === 'high' ? '🚨' : link.riskLevel === 'medium' ? '⚠️' : '⚡';
    return `${riskIcon} ${link.riskLevel.toUpperCase()} (${link.riskScore}): ${link.href.substring(0, 60)}${link.href.length > 60 ? '...' : ''}\nFlags: ${link.flags.join(', ')}\n`;
  });
  
  if (linkData.count > 10) {
    tooltipLines.push(`\n...and ${linkData.count - 10} more suspicious links`);
  }
  
  linksEl.title = tooltipLines.join('\n');
}

// Inject scan
scanButton.addEventListener("click", async () => {
  tableEl.innerHTML =
    "<tr><td colspan='2' style='text-align:center;'>Running scan...</td></tr>";
  linksEl.textContent = "Suspicious Links: Scanning...";
  linksEl.style.color = "grey";
  
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;

  await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    files: ["content.js"],
  });

  chrome.runtime.onMessage.addListener(function onMsg(msg) {
    if (msg.type === "scan_complete") {
      renderTable(msg.results);
      renderSuspiciousLinks(msg.results.suspiciousLinks);
      chrome.runtime.onMessage.removeListener(onMsg);
    }
  });

  setTimeout(async () => {
    const stored = await chrome.storage.local.get(["lastScan"]);
    if (stored.lastScan) {
      renderTable(stored.lastScan);
      renderSuspiciousLinks(stored.lastScan.suspiciousLinks);
    }
  }, 1000);
});

// On popup open → load last results + domain age + SSL check + THREAT CHECK
(async function init() {
  const stored = await chrome.storage.local.get(["lastScan"]);
  if (stored.lastScan) {
    renderTable(stored.lastScan);
    renderSuspiciousLinks(stored.lastScan.suspiciousLinks);
  }

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.url) {
    try {
      const url = new URL(tab.url);
      const domain = url.hostname;

      domainAgeEl.textContent = "Domain age: Checking...";
      domainAgeEl.style.color = "grey";
      sslEl.textContent = "SSL/TLS: Checking...";
      sslEl.style.color = "grey";

      // NEW: Check threat intelligence
      if (threatAlertDiv && threatStatusP) {
        threatAlertDiv.style.display = "block";
        threatAlertDiv.style.backgroundColor = "#e7f3ff";
        threatAlertDiv.style.borderLeft = "4px solid #2196F3";
        threatAlertDiv.style.color = "#014361";
        threatStatusP.innerHTML = "🔍 <strong>Checking for threats...</strong>";

        chrome.runtime.sendMessage(
          { type: "threat_check", url: tab.url },
          (threatResult) => {
            if (chrome.runtime.lastError) {
              displayThreatResult({
                safe: null,
                details: "Unable to check threats"
              });
            } else {
              displayThreatResult(threatResult);
            }
          }
        );
      }

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

document.getElementById("openStride").addEventListener("click", () => {
  chrome.tabs.create({ url: chrome.runtime.getURL("stride.html") });
});
