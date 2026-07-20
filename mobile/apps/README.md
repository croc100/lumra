# Lumra mobile app shells (host mode B — standalone monitoring)

These are the native app shells that turn the gomobile-bound Lumra core into a
shippable, standalone **monitoring** app on iOS and Android. They run Lumra's
_monitor-only_ tunnel (mode B in [`../README.md`](../README.md)): capture every
IP packet, feed it to the cockpit for diagnosis, and write it straight back out
untouched. **Observe-only — Lumra never routes or circumvents** (that is
warren's role; mode A embeds this same core inside warren instead).

The Go core is complete and tested. These shells are the platform glue; they
compile once you drop in the gomobile-built framework — which needs Xcode /
Android SDK + the gomobile toolchain, not present in the core repo's CI.

## 1. Build the binding

```sh
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
gomobile bind -target=ios     -o Lumra.xcframework github.com/croc100/lumra/mobile
gomobile bind -target=android -o lumra.aar          github.com/croc100/lumra/mobile
```

## 2. iOS (`ios/`)

An App + a Packet Tunnel Network Extension target.

| File | Target | Role |
|------|--------|------|
| `LumraApp.swift` | App | SwiftUI UI; starts/stops the tunnel via `NETunnelProviderManager`, polls & renders the board. |
| `PacketTunnelProvider.swift` | Extension | `NEPacketTunnelProvider`: read → `cockpit.feed` → write through; publishes `boardJSON()`. |
| `BoardBridge.swift` | Both | App Group file bridge (extension writes the board, app reads it) + `BoardRow` decoder. |

Setup:
- Add `Lumra.xcframework` to the **extension** target.
- Enable the **App Groups** capability on both targets and set the id in
  `BoardBridge.swift` (`AppGroup.identifier`).
- Set the extension's bundle id in `LumraApp.swift`
  (`providerBundleIdentifier`) to match the extension target.
- Add the **Network Extensions** (Packet Tunnel) capability.

## 3. Android (`android/`)

A single app module.

| File | Role |
|------|------|
| `MainActivity.kt` | Jetpack Compose UI; VPN-consent flow, start/stop, board polling. |
| `LumraVpnService.kt` | `VpnService`: establish tunnel, read → `cockpit.feed` → write through; publishes the board to `filesDir/board.json`. |
| `AndroidManifest.xml` | Manifest fragment (VpnService + launcher activity). |

Setup:
- Put `lumra.aar` in `app/libs/` and add
  `implementation(files("libs/lumra.aar"))` to the module `build.gradle`.
- Compose + `org.json` are the only other deps.

## Board JSON shape

Both UIs decode the array `mobile.Cockpit.BoardJSON()` returns — one object per
domain, mirroring `internal/live.Row`:

```json
[{ "domain": "...", "nature": "control|surveillance|degradation|fault|none|unknown",
   "badge": "…", "tls": "…", "status": "…",
   "who": "…", "why": "…", "action": "…", "enforced": "…" }]
```

`who`/`why`/`action`/`enforced` are omitted until known. Colour rows by
`nature`; the shells already map control→red, surveillance→purple,
degradation→orange, fault→yellow.
