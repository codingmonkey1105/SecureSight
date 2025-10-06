// content.js
if (window.__secureSightInjected) {
  console.log("SecureSight: content script already injected.");
} else {
  window.__secureSightInjected = true;

  console.log("content.js injected successfully!");

  (async function() {
    console.log("---- Running Basic Phishing Checks ----");

    // load patterns.json (optional). Put patterns.json at extension root.
    // let patterns = [];
    // try {
    //   const url = chrome.runtime.getURL("patterns.json");
    //   const resp = await fetch(url);
    //   if (resp.ok) patterns = await resp.json();
    // } catch (e) {
    //   // no patterns.json or failed to load
    //   console.warn("SecureSight: no external patterns loaded.", e);
    // }

    // 1. HTTPS check
    if (window.location.protocol !== "https:") {
      console.log("Site is not using HTTPS.");
    } else {
      console.log("Site uses HTTPS.");
    }

    // 2. URL checks
    const url = window.location.href;

    if ((url.match(/\./g) || []).length > 3) {
      console.log("Suspicious: Too many subdomains in URL.");
    }

    if (/[а-яА-Я]/.test(url)) {
      console.log("Suspicious: URL contains unusual characters (Cyrillic).");
    }

    // built-in quick patterns + external patterns from patterns.json
    const builtinPattern = /g00gle|paypa1|faceb00k/i;
    if (builtinPattern.test(url)) {
      console.log("Possible typosquatting detected (builtin pattern).");
    }

    // try {
    //   if (Array.isArray(patterns) && patterns.length) {
    //     for (const p of patterns) {
    //       // each entry in patterns.json can be a string or regex-string, e.g. "paypa1"
    //       const re = new RegExp(p, "i");
    //       if (re.test(url)) {
    //         console.log(`Possible typosquatting detected (patterns.json): ${p}`);
    //         break;
    //       }
    //     }
    //   }
    // } catch (e) {
    //   console.warn("SecureSight: patterns check failed", e);
    // }

    // 3. Title vs domain
    const title = (document.title || "").toLowerCase();
    const domain = (window.location.hostname || "").toLowerCase();
    const parts = domain.split(".");
    const mainWord = parts.length > 1 ? parts[parts.length - 2] : parts[0];

    if (mainWord && !title.includes(mainWord)) {
      console.log("Title does not match domain name closely.");
    } else {
      console.log("Title seems consistent with domain.");
    }

    // 4. External scripts
    const scripts = [...document.querySelectorAll("script[src]")];
    scripts.forEach(s => {
      if (!s.src.includes(window.location.hostname)) {
        console.log(` External script detected: ${s.src}`);
      }
    });

    if (scripts.length === 0) {
      console.log("No external scripts found.");
    }

    console.log("---- Checks Completed ----");
  })();
}
