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

// --- 1b. Live traffic sensor → local cockpit ---------------------------------
//
// When the user opts in (popup toggle, which also grants <all_urls>), we observe
// every request the browser makes and stream it to `lumra serve` at
// COCKPIT/api/observe. This is the privilege-free counterpart to the raw-socket
// passive tap: the cockpit's live board fills from the browser, no elevation.
// Observations are batched and sent only to localhost; nothing leaves the machine.

const COCKPIT = "http://127.0.0.1:7777";
const OBSERVE_URL = COCKPIT + "/api/observe";

let streaming = false;
let buffer = [];
let flushTimer = null;

chrome.storage.local.get("streaming", (r) => { streaming = !!r.streaming; });
chrome.storage.onChanged.addListener((c) => {
  if (c.streaming) { streaming = !!c.streaming.newValue; if (!streaming) buffer = []; }
});

// hostOf returns the hostname for an http(s) URL, or "" for anything we should
// not report (the cockpit itself, localhost, extension pages, non-web schemes).
function hostOf(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return "";
    const h = u.hostname;
    if (h === "127.0.0.1" || h === "localhost" || h === "[::1]") return "";
    return h;
  } catch { return ""; }
}

function record(url, event, error) {
  if (!streaming) return;
  const domain = hostOf(url);
  if (!domain) return;
  buffer.push(error ? { domain, event, error } : { domain, event });
  if (buffer.length >= 200) return flush();
  if (!flushTimer) flushTimer = setTimeout(flush, 800);
}

function flush() {
  clearTimeout(flushTimer);
  flushTimer = null;
  if (!buffer.length) return;
  const batch = buffer;
  buffer = [];
  fetch(OBSERVE_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(batch),
  }).catch(() => { /* cockpit not running — drop this batch silently */ });
}

chrome.webRequest.onBeforeRequest.addListener(
  (d) => record(d.url, "request"), { urls: ["<all_urls>"] });
chrome.webRequest.onCompleted.addListener(
  (d) => record(d.url, "response"), { urls: ["<all_urls>"] });
chrome.webRequest.onErrorOccurred.addListener(
  (d) => { if (d.error !== "net::ERR_ABORTED") record(d.url, "error", d.error); },
  { urls: ["<all_urls>"] });

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
