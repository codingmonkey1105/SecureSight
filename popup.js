document.getElementById("scanButton").addEventListener("click", async () => {

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) {
      statusEl.textContent = "No active tab found.";
      return;
    }

    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: ["content.js"]
    });

  } catch (err) {
    console.error("Injection error:", err);
    statusEl.textContent = "Failed to inject script.";
  }
});
