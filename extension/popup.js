// Lumra popup: diagnose the active tab's host via the native core and render the
// verdict.

const BAD_TYPES = new Set([
  "DNS_TAMPERING", "SNI_FILTERING", "RST_INJECTION", "IP_BLOCKING",
  "TLS_MITM", "BLOCK_PAGE", "THROTTLING",
]);

const $ = (id) => document.getElementById(id);

let currentHost = "";

// Show the active tab's host.
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  try {
    currentHost = new URL(tabs[0].url).hostname;
  } catch {
    currentHost = "";
  }
  $("target").textContent = currentHost || "(no diagnosable site in this tab)";
  $("run").disabled = !currentHost;
});

$("run").addEventListener("click", () => {
  if (!currentHost) return;
  $("run").disabled = true;
  $("run").textContent = "Diagnosing…";
  $("err").style.display = "none";
  $("verdict").style.display = "none";

  chrome.runtime.sendMessage({ type: "diagnose", target: currentHost }, (resp) => {
    $("run").disabled = false;
    $("run").textContent = "Diagnose this site";

    if (!resp || resp.error) {
      renderError(resp);
      return;
    }
    render(resp.verdict);
  });
});

// --- Live traffic streaming toggle ------------------------------------------
// Enabling requires the <all_urls> host permission (requested here so it is
// granted from a user gesture) plus a stored flag the background reads.
const streamBox = $("stream");
const ALL_URLS = { origins: ["<all_urls>"] };

chrome.storage.local.get("streaming", (r) => { streamBox.checked = !!r.streaming; });

streamBox.addEventListener("change", () => {
  if (streamBox.checked) {
    chrome.permissions.request(ALL_URLS, (granted) => {
      if (!granted) { streamBox.checked = false; return; }
      chrome.storage.local.set({ streaming: true });
    });
  } else {
    chrome.storage.local.set({ streaming: false });
    chrome.permissions.remove(ALL_URLS, () => {});
  }
});

function renderError(resp) {
  const el = $("err");
  el.style.display = "block";
  if (resp && resp.coreMissing) {
    el.innerHTML =
      "The Lumra core is not installed. Install the native binary and run " +
      "<code>lumra install-host</code>, then reload.";
  } else {
    el.textContent = "Diagnosis failed: " + ((resp && resp.error) || "unknown error");
  }
}

function render(v) {
  if (!v) { renderError({ error: "empty verdict" }); return; }

  const bad = BAD_TYPES.has(v.type);
  const typeEl = $("type");
  typeEl.textContent = v.type + (v.confidence ? `  (${v.confidence})` : "");
  typeEl.className = "type " + (bad ? "bad" : "ok");

  const attr = $("attr");
  if (v.attribution) {
    attr.style.display = "block";
    attr.textContent =
      "origin: " + v.attribution + (v.authority ? ` / ${v.authority}` : "");
  } else {
    attr.style.display = "none";
  }

  $("cause").textContent = v.cause || "";

  const ul = $("evidence");
  ul.innerHTML = "";
  for (const e of v.evidence || []) {
    const li = document.createElement("li");
    li.className = e.outcome; // pass | fail | info
    const mark = e.outcome === "pass" ? "✓" : e.outcome === "fail" ? "✗" : "ⓘ";
    li.innerHTML =
      `<span class="m">${mark}</span>` +
      `<span class="probe">${e.probe}</span>` +
      `<span>${escapeHtml(e.detail)}</span>`;
    ul.appendChild(li);
  }
  $("verdict").style.display = "block";
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
