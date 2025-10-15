// favicon_whitelist_setup.js
// Usage:
// 1. Open chrome://extensions -> find your extension -> "Service worker" -> Inspect (open background console).
// 2. Paste this entire file into the console and press Enter.
// 3. Call seedWhitelist(domains) with an array of { domain, label } items.
//    Example:
//      seedWhitelist([
//        { domain: "https://www.google.com", label: "Google" },
//        { domain: "https://www.paypal.com", label: "PayPal" }
//      ]);
//
// Note: this opens temporary tabs (background), injects a script into each page to fetch & hash the favicon,
// and stores results to chrome.storage.local.faviconHashWhitelist as { "<sha256>": "<label>" }.

(async function globalFaviconWhitelistSetup() {
  // Helper: wait for a tab to finish loading (status === 'complete')
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

  // Function that will be injected into each page to find & hash favicon.
  // This runs IN THE PAGE CONTEXT (so it can access page origin resources).
  async function getFaviconHashInPage() {
    // Return an object: { faviconUrl, sha256Hex } or { error: "..." }
    function toHex(buffer) {
      const bytes = new Uint8Array(buffer);
      return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    }

    async function computeSha256FromUrl(url) {
      try {
        const resp = await fetch(url, { mode: "cors" });
        if (!resp.ok) throw new Error("Fetch failed: " + resp.status);
        const ab = await resp.arrayBuffer();
        const hashBuf = await crypto.subtle.digest("SHA-256", ab);
        return toHex(hashBuf);
      } catch (err) {
        throw err;
      }
    }

    try {
      // Find favicon link candidates
      const relSelectors = [
        "link[rel~='icon']",
        "link[rel='shortcut icon']",
        "link[rel='apple-touch-icon']",
        "link[rel='apple-touch-icon-precomposed']",
      ];
      let faviconUrl = null;
      for (const sel of relSelectors) {
        const el = document.querySelector(sel);
        if (el && el.href) {
          faviconUrl = el.href;
          break;
        }
      }
      // fallback to /favicon.ico
      if (!faviconUrl) faviconUrl = `${location.origin}/favicon.ico`;

      // Normalize to absolute URL:
      faviconUrl = new URL(faviconUrl, location.href).href;

      // Try to compute sha256
      const sha = await computeSha256FromUrl(faviconUrl);
      return { faviconUrl, sha256: sha };
    } catch (err) {
      return { error: String(err) };
    }
  }

  // The main function to call from background console:
  async function seedWhitelist(domainItems = []) {
    if (!Array.isArray(domainItems) || domainItems.length === 0) {
      console.error(
        "Pass an array of { domain, label } items to seedWhitelist()."
      );
      return;
    }

    console.log(
      "Starting favicon whitelist seeding for",
      domainItems.length,
      "domains..."
    );

    const results = {}; // sha -> label

    for (const item of domainItems) {
      const domain = item.domain;
      const label = item.label || item.domain;
      if (!domain || typeof domain !== "string") {
        console.warn("Skipping invalid item:", item);
        continue;
      }

      console.log(`Processing ${domain} (${label}) ...`);
      try {
        // Open a background tab for the domain (not active)
        const tab = await new Promise((resolve) =>
          chrome.tabs.create({ url: domain, active: false }, resolve)
        );
        if (!tab || !tab.id) {
          console.warn("Failed to create tab for", domain);
          continue;
        }
        const tabId = tab.id;

        try {
          // Wait for the page to finish loading
          await waitForTabComplete(tabId, 25000);
        } catch (err) {
          console.warn(
            `Tab for ${domain} did not finish loading in time:`,
            err
          );
          // continue anyway — try to inject (some pages might still allow script)
        }

        // Inject getFaviconHashInPage function and run it
        const execRes = await chrome.scripting.executeScript({
          target: { tabId: tabId },
          func: getFaviconHashInPage,
          world: "MAIN", // run in page context for best access to page resources
        });

        // `execRes` is an array; result is in execRes[0].result
        const payload = (execRes && execRes[0] && execRes[0].result) || null;

        if (!payload) {
          console.warn(`No result from page for ${domain}.`);
        } else if (payload.error) {
          console.warn(`Error computing favicon for ${domain}:`, payload.error);
        } else if (payload.sha256) {
          console.log(
            `Domain ${domain} => favicon: ${payload.faviconUrl}, sha256: ${payload.sha256}`
          );
          // Store sha -> label mapping
          results[payload.sha256] = label;
        } else {
          console.warn(`Unexpected payload for ${domain}:`, payload);
        }

        // Close the temporary tab
        try {
          chrome.tabs.remove(tabId);
        } catch (e) {
          // ignore
        }

        // Small delay to avoid overwhelming the browser
        await new Promise((r) => setTimeout(r, 500));
      } catch (err) {
        console.error(`Failed processing ${domain}:`, err);
      }
    } // end loop

    // Merge with any existing whitelist
    const existing = await new Promise((resolve) =>
      chrome.storage.local.get(["faviconHashWhitelist"], resolve)
    );
    const existingMap = (existing && existing.faviconHashWhitelist) || {};

    const merged = Object.assign({}, existingMap, results);

    // Save to chrome.storage.local
    await new Promise((resolve) =>
      chrome.storage.local.set({ faviconHashWhitelist: merged }, resolve)
    );

    console.log(
      "Favicon whitelist seeding complete. Saved entries:",
      Object.keys(results).length
    );
    console.log("Final whitelist keys (hashes):", Object.keys(merged));
    console.log("Preview mapping (sha -> label):", merged);

    return merged;
  }

  // Expose seedWhitelist to the global scope of the service worker console
  // so you can call it manually after pasting this file.
  window.seedWhitelist = seedWhitelist;

  console.log(
    "favicon_whitelist_setup loaded. Call seedWhitelist([{domain, label}, ...]) to run."
  );
})();
