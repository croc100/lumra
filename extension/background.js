// Lumra service worker.
//
// Two jobs:
//  1. Flag failing navigations in-browser (badge) so the user is prompted to
//     diagnose a page that just failed to load.
//  2. Bridge the popup to the local native core over Native Messaging.

const HOST = "net.crode.lumra";

// --- 1. Detect a failing page and badge the tab ------------------------------

// Errors that plausibly indicate interference (not user aborts).
const INTERFERENCE_ERRORS = new Set([
  "net::ERR_CONNECTION_RESET",
  "net::ERR_CONNECTION_TIMED_OUT",
  "net::ERR_CONNECTION_REFUSED",
  "net::ERR_NAME_NOT_RESOLVED",
  "net::ERR_SSL_PROTOCOL_ERROR",
  "net::ERR_CERT_AUTHORITY_INVALID",
  "net::ERR_TIMED_OUT",
]);

chrome.webNavigation.onErrorOccurred.addListener((details) => {
  if (details.frameId !== 0) return; // main frame only
  if (!INTERFERENCE_ERRORS.has(details.error)) return;
  chrome.action.setBadgeText({ tabId: details.tabId, text: "!" });
  chrome.action.setBadgeBackgroundColor({ tabId: details.tabId, color: "#c0392b" });
});

// Clear the badge once a tab successfully completes a navigation.
chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return;
  chrome.action.setBadgeText({ tabId: details.tabId, text: "" });
});

// --- 2. Native-messaging bridge ---------------------------------------------

// The popup asks the background to run a diagnosis; we forward to the native
// core and relay the verdict (or a clear error if the core is not installed).
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type !== "diagnose" || !msg.target) return false;
  chrome.runtime.sendNativeMessage(HOST, { target: msg.target }, (resp) => {
    if (chrome.runtime.lastError) {
      sendResponse({ error: chrome.runtime.lastError.message, coreMissing: true });
      return;
    }
    sendResponse(resp);
  });
  return true; // async response
});
