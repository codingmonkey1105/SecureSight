/**
 * Adds the combined risk-score card to the popup WITHOUT editing popup.js.
 * It wraps the existing render functions (renderDomainAge, renderSSLInfo, displayThreatResult,
 * renderSuspiciousLinks, renderTable) to collect their data, then recomputes the verdict.
 *
 * Load order in popup.html (after popup.js):
 *   <script src="risk-engine.js"></script>
 *   <script src="risk-ui.js"></script>
 */
(function () {
  "use strict";
  if (typeof RiskEngine === "undefined") return;

  const signals = {
    url: "",
    domainAgeDays: null,
    ssl: null,
    safeBrowsingThreat: null,
    suspiciousScripts: null,
    suspiciousLinks: null,
  };
  let model = null; // optional ML weights (model-weights.json)
  let card = null;

  const COLORS = {
    Low: { bg: "#e8f5e9", bar: "#2e7d32", text: "#1b5e20" },
    Medium: { bg: "#fff8e1", bar: "#f9a825", text: "#8d6e00" },
    High: { bg: "#ffebee", bar: "#c62828", text: "#8e1a1a" },
  };

  function el(tag, styles, text) {
    const e = document.createElement(tag);
    if (styles) Object.assign(e.style, styles);
    if (text !== undefined) e.textContent = text; // textContent only: URLs and reasons are never parsed as HTML
    return e;
  }

  function ensureCard() {
    if (card) return card;
    card = el("div", { margin: "12px 0", padding: "10px", borderRadius: "6px", fontSize: "13px" });
    card.id = "riskCard";
    const h1 = document.querySelector("h1");
    if (h1 && h1.parentNode) h1.parentNode.insertBefore(card, h1.nextSibling);
    else document.body.insertBefore(card, document.body.firstChild);
    return card;
  }

  function render() {
    if (!signals.url) return;
    const r = RiskEngine.computeRisk(signals, { model });
    const c = COLORS[r.level];
    const box = ensureCard();
    box.style.background = c.bg;
    box.style.color = c.text;
    box.replaceChildren();

    box.appendChild(el("div", { fontWeight: "700", fontSize: "15px" }, `Risk score: ${r.score}/100 (${r.level})`));

    const track = el("div", { height: "8px", background: "#ddd", borderRadius: "4px", margin: "6px 0", overflow: "hidden" });
    track.appendChild(el("div", { height: "100%", width: r.score + "%", background: c.bar }));
    box.appendChild(track);

    if (r.reasons.length) {
      const ul = el("ul", { margin: "4px 0 0 0", paddingLeft: "18px" });
      r.reasons.slice(0, 5).forEach((x) => ul.appendChild(el("li", null, `${x.label} (+${Math.round(x.points)})`)));
      box.appendChild(ul);
    } else {
      box.appendChild(el("div", null, "No risk indicators found so far."));
    }

    const note = r.missing.length
      ? `Based on ${5 - r.missing.length} of 5 live checks. Not yet available: ${r.missing.join(", ")}.`
      : "Based on all 5 live checks.";
    box.appendChild(el("div", { marginTop: "6px", fontSize: "11px", opacity: "0.8" }, note));
    if (r.missing.includes("page scripts") || r.missing.includes("page links")) {
      box.appendChild(el("div", { fontSize: "11px", opacity: "0.8" }, "Click 'Scan site now' to add page checks."));
    }
  }

  function update(patch) {
    Object.assign(signals, patch);
    render();
  }

  // Call the original function first-class, then feed its data to the risk engine. Never break the popup.
  function wrap(name, collect) {
    const original = window[name];
    if (typeof original !== "function") return;
    window[name] = function () {
      try {
        collect.apply(null, arguments);
      } catch (e) {
        console.warn("[risk-ui]", name, e);
      }
      return original.apply(this, arguments);
    };
  }

  function linkCounts(d) {
    if (!d) return null;
    const list = Array.isArray(d.links) ? d.links : [];
    return {
      high: list.filter((l) => l.riskLevel === "high").length,
      medium: list.filter((l) => l.riskLevel === "medium").length,
    };
  }

  wrap("renderDomainAge", (createdDate) => {
    const ms = createdDate ? Date.now() - new Date(createdDate).getTime() : NaN;
    update({ domainAgeDays: isFinite(ms) ? Math.floor(ms / 86400000) : null });
  });
  wrap("renderSSLInfo", (info) => {
    update({ ssl: info && !info.error && typeof info.valid === "boolean" ? { valid: info.valid } : null });
  });
  wrap("displayThreatResult", (r) => {
    update({ safeBrowsingThreat: r && r.safe === false ? true : r && r.safe === true ? false : null });
  });
  wrap("renderSuspiciousLinks", (d) => {
    if (d) update({ suspiciousLinks: linkCounts(d) });
  });
  wrap("renderTable", (scan) => {
    if (!scan) return;
    const patch = {};
    if (scan.susScripts) patch.suspiciousScripts = !!scan.susScripts.found;
    if (scan.suspiciousLinks) patch.suspiciousLinks = linkCounts(scan.suspiciousLinks);
    if (Object.keys(patch).length) update(patch);
  });

  // Start: URL features are available immediately, no network needed.
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs && tabs[0];
    if (tab && tab.url && /^https?:/i.test(tab.url)) update({ url: tab.url });
  });

  // Optional: upgrade the URL score to the trained model if model-weights.json is bundled.
  fetch(chrome.runtime.getURL("model-weights.json"))
    .then((r) => (r.ok ? r.json() : null))
    .then((m) => {
      if (m && Array.isArray(m.features)) {
        model = m;
        render();
      }
    })
    .catch(() => {});
})();
