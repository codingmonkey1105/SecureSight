// favicon_whitelist_setup.js - FINAL WORKING VERSION
// This version fetches favicons directly from the background script (service worker)
// instead of injecting code into pages.

// Usage:
// 1. Open chrome://extensions -> find your extension -> "Service worker" -> Inspect
// 2. Type "allow pasting" and press Enter
// 3. Paste this entire file into the console and press Enter
// 4. Call seedWhitelist([{domain, label}, ...])

(async function globalFaviconWhitelistSetup() {
  
  // Helper: wait for a tab to finish loading
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

  // Helper: compute SHA-256 hash from ArrayBuffer
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

  // ✅ NEW APPROACH: Fetch favicon directly from background using chrome.tabs API
  async function getFaviconHashForTab(tabId, pageUrl) {
    try {
      // Get tab info to access favicon URL
      const tab = await chrome.tabs.get(tabId);
      
      if (!tab.favIconUrl) {
        console.warn(`No favicon URL available for ${pageUrl}`);
        return { error: "No favicon URL" };
      }

      console.log(`✓ Found favicon URL: ${tab.favIconUrl}`);

      // Fetch the favicon (this works in background/service worker context!)
      const response = await fetch(tab.favIconUrl);
      if (!response.ok) {
        throw new Error(`Fetch failed: ${response.status}`);
      }

      const arrayBuffer = await response.arrayBuffer();
      const sha256 = await computeSha256(arrayBuffer);

      console.log(`✓ Computed hash: ${sha256}`);

      return {
        faviconUrl: tab.favIconUrl,
        sha256: sha256
      };

    } catch (err) {
      console.error(`Error fetching favicon:`, err);
      return { error: String(err) };
    }
  }

  // Main function to seed the whitelist
  async function seedWhitelist(domainItems = []) {
    if (!Array.isArray(domainItems) || domainItems.length === 0) {
      console.error("Pass an array of { domain, label } items to seedWhitelist().");
      return;
    }

    console.log(
      `Starting favicon whitelist seeding for ${domainItems.length} domains...`
    );

    const results = {}; // sha256 -> label

    for (const item of domainItems) {
      const domain = item.domain;
      const label = item.label || item.domain;
      
      if (!domain || typeof domain !== "string") {
        console.warn("Skipping invalid item:", item);
        continue;
      }

      console.log(`\nProcessing ${domain} (${label}) ...`);
      
      try {
        // Open a background tab
        const tab = await chrome.tabs.create({ url: domain, active: false });
        
        if (!tab || !tab.id) {
          console.warn(`Failed to create tab for ${domain}`);
          continue;
        }

        const tabId = tab.id;

        try {
          // Wait for page to load (this also allows time for favicon to load)
          await waitForTabComplete(tabId, 25000);
          
          // Give extra time for favicon to be detected by Chrome
          await new Promise(resolve => setTimeout(resolve, 2000));

        } catch (err) {
          console.warn(`Tab loading timeout for ${domain}:`, err);
        }

        // Get the favicon hash
        const result = await getFaviconHashForTab(tabId, domain);

        if (result.error) {
          console.warn(`❌ Error for ${domain}: ${result.error}`);
        } else if (result.sha256) {
          console.log(`✅ Success for ${domain}`);
          console.log(`   Favicon: ${result.faviconUrl}`);
          console.log(`   Hash: ${result.sha256}`);
          results[result.sha256] = label;
        }

        // Close the tab
        try {
          await chrome.tabs.remove(tabId);
        } catch (e) {
          // ignore
        }

        // Small delay between domains
        await new Promise(resolve => setTimeout(resolve, 1000));

      } catch (err) {
        console.error(`Failed processing ${domain}:`, err);
      }
    }

    // Save results to storage
    const existing = await chrome.storage.local.get(["faviconHashWhitelist"]);
    const existingMap = existing?.faviconHashWhitelist || {};
    const merged = { ...existingMap, ...results };

    await chrome.storage.local.set({ faviconHashWhitelist: merged });

    console.log(`\n✅ Favicon whitelist seeding complete!`);
    console.log(`   New entries added: ${Object.keys(results).length}`);
    console.log(`   Total entries: ${Object.keys(merged).length}`);
    console.log(`\nWhitelist mapping:`, merged);

    return merged;
  }

  // Expose to global scope (use globalThis for service workers)
  globalThis.seedWhitelist = seedWhitelist;

  console.log("✅ favicon_whitelist_setup loaded!");
  console.log("Call: seedWhitelist([{domain, label}, ...])");
})();