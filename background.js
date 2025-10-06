// Runs once when the extension is installed
chrome.runtime.onInstalled.addListener(() => {
  console.log("SecureSight extension installed.");
});

// Runs when the user clicks the extension icon
chrome.action.onClicked.addListener(async (tab) => {
  try {
    // Inject the content script into the current active tab
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: ["content.js"]
    });

    console.log("SecureSight scan started on this page.");
  } catch (error) {
    console.error("Failed to inject SecureSight script:", error);
  }
});
