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
      contentIntegrity: {},
      suspiciousSummary: {},
    };

    // ---------------------
    // Content Integrity Check
    // ---------------------
    try {
      const hostname = results.hostname.toLowerCase();
      const title = (document.title || "").toLowerCase();
      const h1s = [...document.querySelectorAll("h1")].map((h) =>
        h.textContent.toLowerCase()
      );

      const domainBrand = hostname.split(".")[hostname.split(".").length - 2]; // e.g., "google"
      const titleOk = title.includes(domainBrand);
      const h1Ok = h1s.every((h) => h.includes(domainBrand));
      const urlOk = window.location.href.toLowerCase().includes(domainBrand);

      results.contentIntegrity = {
        integrityOk: titleOk && h1Ok && urlOk,
        details: { titleOk, h1Ok, urlOk },
      };
    } catch (err) {
      results.contentIntegrity = { integrityOk: null, details: null };
    }

    // ---------------------
    // URL Checks
    // ---------------------
    try {
      const url = results.url;
      const hostname = results.hostname;

      if ((url.match(/\./g) || []).length > 3)
        results.suspiciousSubdomainCount = true;
      if (/[а-яА-Я]/.test(url)) results.containsCyrillic = true;

      const builtinPattern = /g00gle|paypa1|faceb00k/i;
      results.builtinTyposquatDetected = builtinPattern.test(url);

      const title = (document.title || "").toLowerCase();
      const parts = hostname.split(".");
      const mainWord = parts.length > 1 ? parts[parts.length - 2] : parts[0];
      if (mainWord && !title.includes(mainWord))
        results.titleMatchesDomain = false;
    } catch (err) {
      console.warn("URL check failed:", err);
    }

    // ---------------------
    // External scripts, images, links
    // ---------------------
    try {
      const scripts = [...document.querySelectorAll("script[src]")];
      results.resourceCounts.scripts = scripts.length;

      scripts.forEach((s) => {
        try {
          const srcHostname = new URL(s.src, window.location.origin).hostname;
          if (srcHostname && srcHostname !== results.hostname) {
            results.externalScripts.push(s.src);
            results.resourceCounts.external++;
          }
        } catch {}
      });

      const imgs = [...document.querySelectorAll("img[src]")];
      const links = [...document.querySelectorAll("link[href]")];
      results.resourceCounts.images = imgs.length;
      results.resourceCounts.links = links.length;

      imgs.forEach((i) => {
        try {
          const srcHostname = new URL(i.src, window.location.origin).hostname;
          if (srcHostname && srcHostname !== results.hostname)
            results.resourceCounts.external++;
        } catch {}
      });

      links.forEach((l) => {
        if (!l.href) return;
        try {
          const hrefHostname = new URL(l.href, window.location.origin).hostname;
          if (hrefHostname && hrefHostname !== results.hostname)
            results.resourceCounts.external++;
        } catch {}
      });

      results.resourceCounts.total =
        results.resourceCounts.images +
        results.resourceCounts.scripts +
        results.resourceCounts.links;

      results.resourceAnalysis = {
        externalPercent: results.resourceCounts.total
          ? (results.resourceCounts.external / results.resourceCounts.total) *
            100
          : 0,
        majorityExternal: results.resourceCounts.total
          ? results.resourceCounts.external / results.resourceCounts.total > 0.5
          : false,
      };
    } catch (err) {
      console.warn("Resource analysis failed:", err);
    }

    // ---------------------
    // Favicon hash
    // ---------------------
    try {
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

      let faviconUrl = null;
      const iconEl = document.querySelector("link[rel~='icon']");
      const appleTouch = document.querySelector("link[rel='apple-touch-icon']");
      if (iconEl && iconEl.href)
        faviconUrl = new URL(iconEl.href, window.location.origin).href;
      else if (appleTouch && appleTouch.href)
        faviconUrl = new URL(appleTouch.href, window.location.origin).href;
      else faviconUrl = `${window.location.origin}/favicon.ico`;

      results.favicon.url = faviconUrl;

      try {
        const arr = await fetchAsArrayBuffer(faviconUrl);
        results.favicon.sha256 = await computeSha256(arr);
      } catch {
        results.favicon.sha256 = null;
      }

      const stored = await new Promise((resolve) =>
        chrome.storage.local.get(["faviconHashWhitelist"], resolve)
      );
      const whitelist = (stored && stored.faviconHashWhitelist) || {};
      results.favicon.matchedName =
        results.favicon.sha256 && whitelist[results.favicon.sha256]
          ? whitelist[results.favicon.sha256]
          : null;
    } catch (err) {
      console.warn("Favicon hash failed:", err);
    }

    // ---------------------
    // Suspicious summary
    // ---------------------
    results.suspiciousSummary = {
      nonHttps: !results.isHttps,
      manySubdomains: results.suspiciousSubdomainCount,
      cyrillicInUrl: results.containsCyrillic,
      typosquat: results.builtinTyposquatDetected,
      titleMismatch: !results.titleMatchesDomain,
      externalDominant: results.resourceAnalysis.majorityExternal,
      faviconMismatch: results.favicon.sha256 && !results.favicon.matchedName,
      contentIntegrityMismatch: results.contentIntegrity.integrityOk === false,
    };

    // ---------------------
    // Store results and notify popup
    // ---------------------
    try {
      await new Promise((resolve) =>
        chrome.storage.local.set({ lastScan: results }, resolve)
      );
    } catch (err) {
      console.warn("SecureSight: failed to store results:", err);
    }

    chrome.runtime.sendMessage({ type: "scan_complete", results });
    console.log("SecureSight scan results:", results);
  })();
}
