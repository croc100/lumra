# Lumra on mobile

Lumra is a **diagnosis engine, not a VPN.** It only ever *observes* traffic —
reads packets, never holds, modifies, routes, or re-injects them. Routing around
blocks (the serverless-VPN role) belongs to **warren**, not Lumra.

Because Lumra never owns the network path, it is **source-agnostic**: hand it raw
IPv4 packets from wherever they come and it produces the live board. That gives
two host modes on mobile:

### A. Embedded in warren (primary)

warren owns the on-device serverless-VPN tunnel and does the circumvention. It
embeds Lumra as its diagnosis engine and feeds every tunnel packet to
`Cockpit.Feed`, then renders the board in warren's own UI. This is why there is
no VPN conflict: only warren holds the OS's single VPN slot.

```
warren app  (serverless VPN — routes/circumvents)
  └─ embeds Lumra (diagnosis core)
       ├─ Cockpit.Feed(tunnelPacket)   // observe every packet warren tunnels
       └─ Cockpit.BoardJSON()          // → warren renders "who blocked / watched / down"
```

> **App shells:** ready-to-build native shells for the standalone mode live in
> [`apps/`](apps/) — iOS (`NEPacketTunnelProvider` + SwiftUI) and Android
> (`VpnService` + Compose). Drop in the gomobile framework and build.

### B. Standalone Lumra app (monitoring only)

For pure monitoring with no warren present, Lumra can run its own **monitor-only**
local tunnel — a capture path with no exit server, no circumvention. It reads
packets, passes them straight through untouched, and diagnoses. Note the OS
allows one VPN at a time, so this standalone mode and warren's VPN are mutually
exclusive; when warren is active, use mode A.

Either way the Go core and its analysis (SNI, TLS version, certificate-MITM,
DNS-redirect) are identical — the only difference is who supplies the packets.

## Build the binding

```sh
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init

gomobile bind -target=android -o lumra.aar        github.com/croc100/lumra/mobile
gomobile bind -target=ios     -o Lumra.xcframework github.com/croc100/lumra/mobile
```

## The API (`mobile.Cockpit`) — the warren↔Lumra seam

| Method                | Purpose                                                        |
|-----------------------|---------------------------------------------------------------|
| `NewCockpit()`        | Create once when the tunnel starts.                           |
| `Feed(packet []byte)` | Hand it every raw IPv4 packet the tunnel reads (no framing).  |
| `Board() string`      | Preformatted text board.                                      |
| `BoardJSON() []byte`  | JSON array of rows (`domain, nature, badge, tls, status, …`). |
| `Count() int`         | Number of domains currently monitored.                        |

warren (or a standalone Lumra shell) calls `Feed` in its packet loop and renders
from `BoardJSON`. Lumra returns diagnosis only — it never tells the tunnel to
reroute; what to do about a block is warren's decision.

## Packet loop (either host)

iOS — `NEPacketTunnelProvider`:

```swift
packetFlow.readPackets { packets, protocols in
    for p in packets { cockpit?.feed(p) }                 // observe
    self.packetFlow.write(packets, withProtocols: protocols) // pass through / warren routes
    self.readLoop()
}
```

Android — `VpnService`:

```kotlin
val n = input.read(buf)
if (n > 0) cockpit.feed(buf.copyOf(n))   // observe
// warren forwards buf to its serverless-VPN exit (mode A) or straight out (mode B)
```
