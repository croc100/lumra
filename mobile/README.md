# Lumra on mobile

The mobile clients reuse Lumra's cockpit core unchanged. There is no raw-socket
capture on a phone, so the OS routes traffic through an on-device **VPN tunnel**;
the native provider feeds each packet to this Go core and reads the board back.

Lumra only **observes**: packets are read, never held, modified, or re-injected.
The tunnel is monitor-only — the same passive philosophy as the desktop tap.

## Build the binding

```sh
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init

# Android → lumra.aar
gomobile bind -target=android -o lumra.aar        github.com/croc100/lumra/mobile

# iOS → Lumra.xcframework
gomobile bind -target=ios     -o Lumra.xcframework github.com/croc100/lumra/mobile
```

## The API (`mobile.Cockpit`)

| Method                | Purpose                                                        |
|-----------------------|---------------------------------------------------------------|
| `NewCockpit()`        | Create once when the tunnel starts.                           |
| `Feed(packet []byte)` | Hand it every raw IPv4 packet the tunnel reads (no framing).  |
| `Board() string`      | Preformatted text board.                                      |
| `BoardJSON() []byte`  | JSON array of rows (`domain, nature, badge, tls, status, …`). |
| `Count() int`         | Number of domains currently monitored.                        |

## iOS — NEPacketTunnelProvider (sketch)

```swift
let cockpit = MobileNewCockpit()

func readLoop() {
    packetFlow.readPackets { packets, _ in
        for p in packets { cockpit?.feed(p) }        // observe
        self.packetFlow.write(packets, withProtocols: protocols) // pass through untouched
        self.readLoop()
    }
}
// Render UI from cockpit.boardJSON() on a timer.
```

## Android — VpnService (sketch)

```kotlin
val cockpit = Mobile.newCockpit()
val input = FileInputStream(tunFd.fileDescriptor)
val buf = ByteArray(65535)
while (running) {
    val n = input.read(buf)
    if (n > 0) cockpit.feed(buf.copyOf(n))           // observe
    // forward buf to the real network (pass through untouched)
}
// Render UI from cockpit.boardJSON() on a timer.
```

Everything the desktop does — SNI, TLS version, certificate-MITM, DNS-redirect
detection — runs identically here, because it is the same `internal/live` core.
