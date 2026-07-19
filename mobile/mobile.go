// Package mobile is Lumra's mobile entry point: a gomobile-bindable facade over
// the cockpit core. It is deliberately tiny and uses only bind-safe types
// (string, []byte), so `gomobile bind` produces a clean Android .aar and iOS
// .xcframework.
//
// On the phone there is no raw-socket capture, so the OS routes traffic through
// an on-device VPN tunnel — iOS NEPacketTunnelProvider or Android VpnService.
// The native provider receives each IP packet, hands it to Feed, and reads Board
// or BoardJSON to render the live UI. Exactly the same analysis as the desktop
// tap runs here (SNI, TLS version, certificate MITM, DNS redirect), because it
// is the same core. Packets are only observed — read, never held, modified, or
// re-injected by Lumra — so the tunnel stays monitor-only.
//
// Bind:
//
//	gomobile bind -target=android -o lumra.aar    github.com/croc100/lumra/mobile
//	gomobile bind -target=ios     -o Lumra.xcframework github.com/croc100/lumra/mobile
package mobile

import (
	"encoding/json"

	"github.com/croc100/lumra/internal/live"
)

// Cockpit is the object the native app holds for the lifetime of the tunnel.
type Cockpit struct {
	m *live.Monitor
}

// NewCockpit creates an empty cockpit. Call once when the tunnel starts.
func NewCockpit() *Cockpit {
	return &Cockpit{m: live.NewMonitor()}
}

// Feed hands one raw IPv4 packet (as delivered by the VPN provider, no link-layer
// header) to the cockpit. Call it for every packet the tunnel reads.
func (c *Cockpit) Feed(packet []byte) {
	c.m.HandlePacket(packet)
}

// Board returns the cockpit as preformatted text, for a quick console or a
// monospaced view.
func (c *Cockpit) Board() string {
	return c.m.Render()
}

// BoardJSON returns the board as a JSON array of row objects, for a native UI to
// lay out. Each row carries domain, nature, badge, tls, status, and (when known)
// who/why/action/enforced. Returns "[]" if marshaling ever fails.
func (c *Cockpit) BoardJSON() []byte {
	b, err := json.Marshal(live.Rows(c.m.Snapshot()))
	if err != nil {
		return []byte("[]")
	}
	return b
}

// Count returns how many domains are currently on the board — a cheap value for
// a badge or a "N domains monitored" label without parsing JSON.
func (c *Cockpit) Count() int {
	return len(c.m.Snapshot())
}
