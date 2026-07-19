package live

import (
	"sort"
	"sync"
	"time"

	"github.com/croc100/lumra/internal/verdict"
)

// EventKind marks what the tap observed on the wire.
type EventKind string

const (
	// ClientHello is an outbound handshake carrying an SNI: a domain being reached.
	ClientHello EventKind = "client_hello"
	// ServerHello is the server's reply, from which the negotiated version is read.
	ServerHello EventKind = "server_hello"
	// Reset is a TCP RST observed on a tracked flow — the middlebox block signature.
	Reset EventKind = "reset"
)

// Event is one observation from the tap, already resolved to a domain.
type Event struct {
	Kind    EventKind
	Domain  string
	Version uint16 // negotiated TLS version, ServerHello only
	At      time.Time
}

// Flow is the live state of one domain the host has been talking to.
type Flow struct {
	Domain    string
	FirstSeen time.Time
	LastSeen  time.Time
	Version   uint16 // last negotiated TLS version, 0 if no ServerHello yet
	Handshake bool   // a ServerHello was seen (the session got established)
	Resets    int    // RSTs observed on this domain's flows
	Hits      int    // ClientHellos observed (connection attempts)
}

// Nature is the intuitive, passively-derived character of this flow. It is
// deliberately conservative: a passive tap sees metadata, not content, so it
// only asserts what the wire proves — a reset is a block; everything else that
// completed a handshake is reported clear, leaving deeper surveillance calls to
// an on-demand full diagnosis.
func (f *Flow) Nature() verdict.Nature {
	if f.Resets > 0 && !f.Handshake {
		return verdict.NatureControl // reset with no session ever established
	}
	if f.Handshake {
		return verdict.NatureNone
	}
	return verdict.NatureUnknown // seen attempts but no outcome yet
}

// Tracker keeps the live board. It is safe for concurrent use: the tap feeds
// Observe from one goroutine while the renderer calls Snapshot from another.
type Tracker struct {
	mu    sync.Mutex
	flows map[string]*Flow
}

// NewTracker returns an empty Tracker.
func NewTracker() *Tracker {
	return &Tracker{flows: make(map[string]*Flow)}
}

// Observe folds one tap event into the board.
func (t *Tracker) Observe(e Event) {
	if e.Domain == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.flows[e.Domain]
	if f == nil {
		f = &Flow{Domain: e.Domain, FirstSeen: e.At}
		t.flows[e.Domain] = f
	}
	if e.At.After(f.LastSeen) {
		f.LastSeen = e.At
	}
	switch e.Kind {
	case ClientHello:
		f.Hits++
	case ServerHello:
		f.Handshake = true
		if e.Version != 0 {
			f.Version = e.Version
		}
	case Reset:
		f.Resets++
	}
}

// Snapshot returns a copy of every flow, most-recently-active first, safe to
// render without holding the lock.
func (t *Tracker) Snapshot() []Flow {
	t.mu.Lock()
	out := make([]Flow, 0, len(t.flows))
	for _, f := range t.flows {
		out = append(out, *f)
	}
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}
