# Lumra Browser Extension

Diagnose why the current site is blocked, throttled, or tampered with — right
from the toolbar. The extension is a thin front end; the measurement runs in the
local Lumra native core over [Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging).

## Capability tiers

| Setup | What you get |
|-------|--------------|
| Extension only | in-browser detection of failing navigations (toolbar badge) |
| Extension **+ native core** | full verdict: DNS / SNI / RST-TTL attribution / self-identified block page |
| Extension **+ `lumra serve`** | live traffic board of every domain the browser touches — **no elevation** |

The browser cannot inspect raw packets, so deep attribution (TTL hop
triangulation, injected-RST detection) only works with the native core installed.

## Live traffic streaming → local cockpit

`lumra serve` runs a local web cockpit (`http://127.0.0.1:7777`) with a live
board of interference. Its own passive tap needs elevation (raw sockets), but the
extension is a **privilege-free sensor**: it observes every request the browser
makes (`webRequest`) and streams it to the cockpit, which classifies each domain
(clear / blocked / watched) and shows it on the board in real time.

Turn it on from the popup: **"Stream this browser's traffic to the local
cockpit."** Enabling asks for the `<all_urls>` permission (needed to observe
traffic) and is off by default. Observations go only to `127.0.0.1:7777` — nothing
leaves the machine, in keeping with CRODE's no-log stance. If the cockpit isn't
running, batches are dropped silently.

## Install (Chrome / Edge)

1. **Build the core** and note its path:
   ```
   go build -o lumra ./cmd/lumra
   ```
2. **Load the extension**: go to `chrome://extensions`, enable *Developer mode*,
   *Load unpacked*, and select this `extension/` directory. Copy the extension
   **ID** shown on the card.
3. **Register the native host** (points Chrome at your `lumra` binary):
   ```
   ./lumra install-host <extension-id>
   ```
   This writes `net.crode.lumra.json` into Chrome's `NativeMessagingHosts`
   directory for the current user.
4. Reload the extension. Click the toolbar icon on any site and *Diagnose*.

## Firefox

Firefox uses the same MV3 background/popup code but:
- add a `browser_specific_settings.gecko.id` to `manifest.json`, and
- the native host manifest lives under a different path
  (`~/.mozilla/native-messaging-hosts/` on Linux/macOS) with `allowed_extensions`
  instead of `allowed_origins`.

A Firefox-specific `install-host` mode will land alongside packaging.

## Files

- `manifest.json` — MV3 manifest
- `background.js` — badges failing tabs; streams observed traffic to the cockpit; bridges popup ↔ native core
- `popup.html` / `popup.js` — the diagnose UI + traffic-streaming toggle
- `host/net.crode.lumra.json.template` — reference host manifest (the
  `install-host` command generates the real one with correct paths)

## Windows

Register the host in the registry:
`HKCU\Software\Google\Chrome\NativeMessagingHosts\net.crode.lumra` →
default value = full path to a `net.crode.lumra.json` you place next to the
binary (built from the template). Native `install-host` support for Windows is
planned.
