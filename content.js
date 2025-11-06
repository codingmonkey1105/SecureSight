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
      susScripts: { found: false, details: [] },
      suspiciousLinks: { found: false, count: 0, links: [] },
    };

    // NEW: Scan all links for suspicious patterns
    function scanLinksForThreats() {
      const allLinks = document.querySelectorAll('a[href]');
      const suspiciousLinks = [];
      
      const suspiciousPatterns = {
        typosquatting: /g00gle|faceb00k|paypa1|amaz0n|netfl1x|micr0soft|app1e|tw1tter|inst4gram/i,
        cyrillicHomoglyphs: /[а-яА-Я]/,
        ipAddress: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
        suspiciousTLD: /\.(tk|ml|ga|cf|gq|pw|cc|ws|info|biz|top|xyz|online|site|club)$/i,
        excessiveSubdomains: /^https?:\/\/([a-z0-9-]+\.){4,}/i,
        urlShorteners: /bit\.ly|tinyurl|goo\.gl|ow\.ly|t\.co|shorturl/i,
        suspiciousKeywords: /login|verify|account|suspend|secure|update|confirm|bank|paypal|wallet|crypto/i,
        dataURI: /^data:/i,
        javascriptProtocol: /^javascript:/i,
        homographAttack: /[ρ|о|а|е|у|і|х|с|р|т|ν|μ]/i, // Lookalike characters
      };

      allLinks.forEach(link => {
        try {
          const href = link.href;
          const linkText = link.textContent.trim().toLowerCase();
          const currentDomain = window.location.hostname;
          
          if (!href || href === '#' || href.startsWith('mailto:')) return;

          const flags = [];
          let riskScore = 0;

          // Check for typosquatting
          if (suspiciousPatterns.typosquatting.test(href)) {
            flags.push('Typosquatting detected');
            riskScore += 3;
          }

          // Check for Cyrillic characters
          if (suspiciousPatterns.cyrillicHomoglyphs.test(href)) {
            flags.push('Cyrillic/Unicode characters');
            riskScore += 3;
          }

          // Check for IP addresses
          if (suspiciousPatterns.ipAddress.test(href)) {
            flags.push('Links to IP address');
            riskScore += 2;
          }

          // Check for suspicious TLDs
          if (suspiciousPatterns.suspiciousTLD.test(href)) {
            flags.push('Suspicious domain extension');
            riskScore += 2;
          }

          // Check for excessive subdomains
          if (suspiciousPatterns.excessiveSubdomains.test(href)) {
            flags.push('Too many subdomains');
            riskScore += 2;
          }

          // Check for URL shorteners
          if (suspiciousPatterns.urlShorteners.test(href)) {
            flags.push('URL shortener');
            riskScore += 1;
          }

          // Check for phishing keywords in URL + link text mismatch
          if (suspiciousPatterns.suspiciousKeywords.test(href)) {
            flags.push('Suspicious keywords');
            riskScore += 2;
          }

          // Check for data URI or javascript protocol
          if (suspiciousPatterns.dataURI.test(href) || suspiciousPatterns.javascriptProtocol.test(href)) {
            flags.push('Dangerous protocol');
            riskScore += 3;
          }

          // Check for homograph attacks
          if (suspiciousPatterns.homographAttack.test(href)) {
            flags.push('Possible homograph attack');
            riskScore += 3;
          }

          // Check if link text doesn't match href domain
          try {
            const linkURL = new URL(href);
            const linkDomain = linkURL.hostname;
            
            // If it's external and text suggests it should be the current domain
            if (linkDomain !== currentDomain) {
              if (linkText.includes(currentDomain) || linkText.includes('here') || linkText.includes('click here')) {
                flags.push('Misleading link text');
                riskScore += 2;
              }
            }

            // Check for very new or suspicious domain patterns
            if (linkDomain.length > 30) {
              flags.push('Unusually long domain');
              riskScore += 1;
            }

            // Check for multiple hyphens
            if ((linkDomain.match(/-/g) || []).length > 2) {
              flags.push('Multiple hyphens in domain');
              riskScore += 1;
            }
          } catch (e) {
            // Invalid URL
          }

          // If any flags were raised, add to suspicious links
          if (flags.length > 0 && riskScore >= 2) {
            suspiciousLinks.push({
              href: href,
              text: linkText.substring(0, 50),
              flags: flags,
              riskScore: riskScore,
              riskLevel: riskScore >= 5 ? 'high' : riskScore >= 3 ? 'medium' : 'low'
            });
          }
        } catch (err) {
          console.warn('Error scanning link:', err);
        }
      });

      // Sort by risk score
      suspiciousLinks.sort((a, b) => b.riskScore - a.riskScore);

      return {
        found: suspiciousLinks.length > 0,
        count: suspiciousLinks.length,
        links: suspiciousLinks.slice(0, 20), // Limit to top 20
        totalScanned: allLinks.length
      };
    }

    // Suspicious Scripts Detection (inline, external, dynamic)
    function detectSuspiciousScripts() {
      const susPatterns = [
        /eval\s*\(/i,
        /document\.write\s*\(/i,
        /setTimeout\s*\(\s*['"`]/i,
        /setInterval\s*\(\s*['"`]/i,
        /atob\s*\(/i,
        /btoa\s*\(/i,
        /Function\s*\(/i,
        /[\w$]\s*=\s*atob\s*\(/i,
        /[\w$]\s*=\s*new\s+Function/i,
      ];

      let found = false;
      let details = [];

      // Scan all script tags
      document.querySelectorAll("script").forEach((script) => {
        const code = script.textContent || "";
        susPatterns.forEach((pattern) => {
          if (pattern.test(code)) {
            found = true;
            details.push({
              pattern: pattern.toString(),
              snippet: code.slice(0, 100),
            });
          }
        });
      });

      // Scan the entire HTML as a fallback
      const html = document.documentElement.innerHTML;
      susPatterns.forEach((pattern) => {
        if (pattern.test(html)) {
          found = true;
          details.push({
            pattern: pattern.toString(),
            snippet: html.match(pattern)[0],
          });
        }
      });

      return { found, details };
    }

    // MutationObserver for dynamically injected scripts
    const dynamicScriptDetails = [];
    const susPatterns = [
      /eval\s*\(/i,
      /document\.write\s*\(/i,
      /setTimeout\s*\(\s*['"`]/i,
      /setInterval\s*\(\s*['"`]/i,
      /atob\s*\(/i,
      /btoa\s*\(/i,
      /Function\s*\(/i,
      /[\w$]\s*=\s*atob\s*\(/i,
      /[\w$]\s*=\s*new\s+Function/i,
    ];
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.tagName === "SCRIPT") {
            const code = node.textContent || "";
            susPatterns.forEach((pattern) => {
              if (pattern.test(code)) {
                dynamicScriptDetails.push({
                  pattern: pattern.toString(),
                  snippet: code.slice(0, 100),
                });
              }
            });
          }
        });
      });
    });
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });

    // Content Integrity Check
    try {
      const hostname = results.hostname.toLowerCase();
      const title = (document.title || "").toLowerCase();
      const h1s = [...document.querySelectorAll("h1")].map((h) =>
        h.textContent.toLowerCase()
      );
      const domainBrand = hostname.split(".")[hostname.split(".").length - 2];
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

    // URL Checks
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

    // External scripts, images, links
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

    // ✅ FIXED: Favicon hash - use same method as background.js
    try {
      console.log('🔍 Starting favicon hash computation...');

      async function getFaviconHash() {
        try {
          // Find favicon URL the same way browser does
          let faviconUrl = null;
          const iconEl = document.querySelector("link[rel~='icon']");
          const appleTouch = document.querySelector("link[rel='apple-touch-icon']");

          if (iconEl && iconEl.href) {
            faviconUrl = new URL(iconEl.href, window.location.origin).href;
          } else if (appleTouch && appleTouch.href) {
            faviconUrl = new URL(appleTouch.href, window.location.origin).href;
          } else {
            faviconUrl = `${window.location.origin}/favicon.ico`;
          }

          console.log('✓ Fetching favicon from:', faviconUrl);

          // Fetch the favicon
          const response = await fetch(faviconUrl, { mode: 'cors' });
          if (!response.ok) {
            throw new Error(`Favicon fetch failed: ${response.status}`);
          }

          const arrayBuffer = await response.arrayBuffer();

          // Compute SHA-256 hash
          const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
          const hashArray = Array.from(new Uint8Array(hashBuffer));
          const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

          console.log('✓ Favicon hash computed:', hashHex);

          return {
            url: faviconUrl,
            sha256: hashHex
          };

        } catch (error) {
          console.error('❌ Favicon hash failed:', error);
          return {
            url: null,
            sha256: null,
            error: error.message
          };
        }
      }

      // Execute the function
      const faviconResult = await getFaviconHash();
      results.favicon.url = faviconResult.url;
      results.favicon.sha256 = faviconResult.sha256;

      // Check against whitelist
      const stored = await new Promise((resolve) =>
        chrome.storage.local.get(['faviconHashWhitelist'], resolve)
      );
      const whitelist = (stored && stored.faviconHashWhitelist) || {};

      console.log('📋 Whitelist entries:', Object.keys(whitelist).length);
      console.log('🔍 Looking for hash:', faviconResult.sha256);

      results.favicon.matchedName =
        results.favicon.sha256 && whitelist[results.favicon.sha256]
          ? whitelist[results.favicon.sha256]
          : null;

      if (results.favicon.matchedName) {
        console.log('✅ FAVICON MATCHED:', results.favicon.matchedName);
      } else {
        console.log('⚠️ Favicon not in whitelist (Unknown site)');
      }

    } catch (err) {
      console.warn('❌ Favicon hash failed:', err);
    }


    // NEW: Scan links for threats
    results.suspiciousLinks = scanLinksForThreats();

    // Suspicious summary
    results.suspiciousSummary = {
      nonHttps: !results.isHttps,
      manySubdomains: results.suspiciousSubdomainCount,
      cyrillicInUrl: results.containsCyrillic,
      typosquat: results.builtinTyposquatDetected,
      titleMismatch: !results.titleMatchesDomain,
      externalDominant: results.resourceAnalysis.majorityExternal,
      faviconMismatch: results.favicon.sha256 && !results.favicon.matchedName,
      contentIntegrityMismatch: results.contentIntegrity.integrityOk === false,
      suspiciousLinksFound: results.suspiciousLinks.found,
    };

    // Listen for popup requests
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
      if (msg.type === "checkSusScripts") {
        sendResponse(detectSuspiciousScripts());
        return true;
      }
      if (msg.type === "getSuspiciousLinks") {
        sendResponse(results.suspiciousLinks);
        return true;
      }
    });

    // Store results and notify popup
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
chrome.runtime.sendMessage({
  type: 'scan_complete',
  nonce: messageAuth.generateNonce(),
  sequence: messageAuth.getNextSequence(),
  timestamp: Date.now(),
  results: results
});