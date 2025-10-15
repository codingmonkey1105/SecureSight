// content.js
if (window.__secureSightInjected) {
  console.log("SecureSight: content script already injected.");
} else {
  window.__secureSightInjected = true;
  console.log("SecureSight content script injected.");

  (async function runChecks() {
    const results = {
      url: window.location.href,
      hostname: window.location.hostname,
      isHttps: window.location.protocol === "https:",
      suspiciousSubdomainCount: false,
      containsCyrillic: false,
      builtinTyposquatDetected: false,
      titleMatchesDomain: true,
      externalScripts: [],
      resourceCounts: {
        total: 0,
        external: 0,
        images: 0,
        scripts: 0,
        links: 0,
      },
      favicon: { url: null, sha256: null, matchedName: null },
      timestamp: new Date().toISOString(),
    };

    try {
      // 1. URL checks
      const url = window.location.href;
      const hostname = window.location.hostname;
      if ((url.match(/\./g) || []).length > 3)
        results.suspiciousSubdomainCount = true;
      if (/[а-яА-Я]/.test(url)) results.containsCyrillic = true;
      const builtinPattern = /g00gle|paypa1|faceb00k/i;
      results.builtinTyposquatDetected = builtinPattern.test(url);

      // 2. Title vs domain
      const title = (document.title || "").toLowerCase();
      const parts = hostname.split(".");
      const mainWord = parts.length > 1 ? parts[parts.length - 2] : parts[0];
      if (mainWord && !title.includes(mainWord))
        results.titleMatchesDomain = false;

      // 3. External scripts & script count
      const scripts = [...document.querySelectorAll("script[src]")];
      results.resourceCounts.scripts = scripts.length;
      scripts.forEach((s) => {
        try {
          const src = s.src;
          const srcHostname = new URL(src, window.location.origin).hostname;
          if (srcHostname && srcHostname !== hostname) {
            results.externalScripts.push(src);
            results.resourceCounts.external++;
          }
        } catch (e) {
          // ignore malformed src
        }
      });

      // 4. Images / links counts & external detection
      const imgs = [...document.querySelectorAll("img[src]")];
      const links = [...document.querySelectorAll("link[href]")];
      results.resourceCounts.images = imgs.length;
      results.resourceCounts.links = links.length;

      // Count external for images
      imgs.forEach((i) => {
        try {
          const srcHostname = new URL(i.src, window.location.origin).hostname;
          if (srcHostname && srcHostname !== hostname)
            results.resourceCounts.external++;
        } catch (e) {}
      });

      // Count external for link[href] (typically css/icons)
      links.forEach((l) => {
        if (!l.href) return;
        try {
          const hrefHostname = new URL(l.href, window.location.origin).hostname;
          if (hrefHostname && hrefHostname !== hostname)
            results.resourceCounts.external++;
        } catch (e) {}
      });

      // Total resource count
      results.resourceCounts.total =
        results.resourceCounts.images +
        results.resourceCounts.scripts +
        results.resourceCounts.links;

      // Compute >50% external flag (store as a helper field)
      results.resourceAnalysis = {
        externalPercent: results.resourceCounts.total
          ? (results.resourceCounts.external / results.resourceCounts.total) *
            100
          : 0,
        majorityExternal: results.resourceCounts.total
          ? results.resourceCounts.external / results.resourceCounts.total > 0.5
          : false,
      };

      // 5. Favicon extraction + hashing
      async function fetchAsArrayBuffer(url) {
        const resp = await fetch(url, { mode: "cors" });
        if (!resp.ok) throw new Error("Fetch failed: " + resp.status);
        return await resp.arrayBuffer();
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

      // try to find favicon
      let faviconUrl = null;
      const iconEl = document.querySelector("link[rel~='icon']");
      const appleTouch = document.querySelector("link[rel='apple-touch-icon']");
      if (iconEl && iconEl.href)
        faviconUrl = new URL(iconEl.href, window.location.origin).href;
      else if (appleTouch && appleTouch.href)
        faviconUrl = new URL(appleTouch.href, window.location.origin).href;
      else {
        // fallback to /favicon.ico
        faviconUrl = `${window.location.origin}/favicon.ico`;
      }

      results.favicon.url = faviconUrl;

      // Attempt to fetch and hash favicon (may fail due to CORS on some sites)
      try {
        const arr = await fetchAsArrayBuffer(faviconUrl);
        const sha = await computeSha256(arr);
        results.favicon.sha256 = sha;
      } catch (err) {
        console.warn("SecureSight: favicon fetch/hash failed:", err);
        results.favicon.sha256 = null;
      }

      // Attempt to match against built-in hash whitelist (we'll store known hashes in extension storage or inline map)
      // We'll query chrome.storage.local for a mapping { "<sha256>": "Name" }
      const stored = await new Promise((resolve) =>
        chrome.storage.local.get(["faviconHashWhitelist"], resolve)
      );
      const whitelist = (stored && stored.faviconHashWhitelist) || {}; // object map sha -> label

      if (results.favicon.sha256 && whitelist[results.favicon.sha256]) {
        results.favicon.matchedName = whitelist[results.favicon.sha256];
      } else {
        results.favicon.matchedName = null;
      }

      // 6. Compose a summary flag for suspiciousness from these metrics
      results.suspiciousSummary = {
        nonHttps: !results.isHttps,
        manySubdomains: results.suspiciousSubdomainCount,
        cyrillicInUrl: results.containsCyrillic,
        typosquat: results.builtinTyposquatDetected,
        titleMismatch: !results.titleMatchesDomain,
        externalDominant: results.resourceAnalysis.majorityExternal,
        faviconMismatch: results.favicon.sha256 && !results.favicon.matchedName, // favicon exists but not matched to known brand hash
      };
    } catch (err) {
      console.error("SecureSight content check failed:", err);
      results.error = String(err);
    }

    // Save results to storage so popup can read immediately
    try {
      await new Promise((resolve) =>
        chrome.storage.local.set({ lastScan: results }, resolve)
      );
    } catch (err) {
      console.warn("SecureSight: failed to store results:", err);
    }

    // Also notify runtime listeners (popup)
    chrome.runtime.sendMessage({ type: "scan_complete", results });

    // Additionally log to console (for debugging / demo)
    console.log("SecureSight scan results:", results);
  })();
}
