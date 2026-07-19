package live

import (
	"sync"
	"time"
)

// Monitor is the embeddable heart of the cockpit: feed it raw IPv4 packets and
// read back the live board. It bundles a dispatcher and a Tracker behind one
// serialized entry point so a single capture source (a desktop tap goroutine or
// a mobile VPN provider's packet callback) can drive it while a UI reads the
// snapshot. It holds no sockets and does no platform I/O, so every backend —
// AF_PACKET, TunSource, or a native tunnel bound via gomobile — shares it.
type Monitor struct {
	mu   sync.Mutex
	disp *dispatcher
	tr   *Tracker
}

// NewMonitor returns a ready Monitor with an empty board.
func NewMonitor() *Monitor {
	tr := NewTracker()
	return &Monitor{disp: newDispatcher(tr.Observe), tr: tr}
}

// HandlePacket parses one raw IPv4 packet (no link-layer framing) and folds any
// observations into the board. Safe to call from one capture goroutine; the lock
// serializes the dispatcher's per-flow state.
func (m *Monitor) HandlePacket(ip []byte) {
	m.mu.Lock()
	m.disp.handle(ip, time.Now())
	m.mu.Unlock()
}

// Snapshot returns the current board, most-recently-active first.
func (m *Monitor) Snapshot() []Flow { return m.tr.Snapshot() }

// Tracker exposes the underlying tracker so an active-mode Escalator can attach.
func (m *Monitor) Tracker() *Tracker { return m.tr }

// Render returns the board formatted for a text display.
func (m *Monitor) Render() string { return RenderBoard(m.tr.Snapshot(), time.Now()) }
