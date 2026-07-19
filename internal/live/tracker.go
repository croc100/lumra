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
	// Cert is a server certificate observed (TLS 1.2 cleartext) and verified
	// against the system roots. Untrusted marks a substituted chain — MITM.
	Cert EventKind = "cert"
	// DNS is a DNS reply whose answer bears an injected-redirect signature
	// (sinkhole/bogon address), read passively off the wire.
	DNS EventKind = "dns"
)

// Event is one observation from the tap, already resolved to a domain.
type Event struct {
	Kind       EventKind
	Domain     string
	Version    uint16 // negotiated TLS version, ServerHello only
	Untrusted  bool   // Cert only: chain does not reach a trusted root (MITM signal)
	Subject    string // Cert only: leaf subject CN, for the evidence line
	Suspicious bool   // DNS only: answer bears an injected-redirect signature
	Reason     string // DNS only: why the answer looks injected
	At         time.Time
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

	// Passive certificate check (TLS 1.2, no active probe): CertChecked once a
	// server cert was observed and verified; CertUntrusted marks a substituted
	// chain — a man-in-the-middle read of the session caught purely by watching.
	CertChecked   bool
	CertUntrusted bool
	CertSubject   string

	// Passive DNS check: a reply for this name carried a sinkhole/bogon answer,
	// the signature of an injected DNS redirect — caught without any resolver.
	DNSInjected bool
	DNSReason   string

	// Deep-analysis result, filled automatically by the Escalator so the board
	// resolves from a passive guess to an authoritative verdict without the user
	// asking. DeepType/Confidence are meaningful only when Analyzed is true.
	Analyzed    bool
	AnalyzedAt  time.Time
	DeepType    verdict.Type
	Confidence  verdict.Confidence
	DeepCause   string              // one-line reason, surfaced automatically (auto drill-down)
	Attribution verdict.Attribution // where the interference originates (who)
	Authority   string              // named operator when the block infra self-identifies (e.g. KCSC)
	Action      Action              // protective policy Lumra applied on its own (auto lever)
	Enforced    string              // summary of the applied enforcement, empty if none
}

// Nature is the intuitive character of this flow. Once the Escalator has run a
// full diagnosis, that authoritative verdict wins; until then the board shows a
// conservative passively-derived guess from wire metadata alone (a reset is a
// block; an established handshake reads clear; anything else is pending).
func (f *Flow) Nature() verdict.Nature {
	if f.Analyzed {
		return verdict.NatureOf(f.DeepType)
	}
	if f.CertUntrusted {
		return verdict.NatureSurveillance // substituted cert caught passively — MITM
	}
	if f.DNSInjected {
		return verdict.NatureControl // DNS redirected to a sinkhole — a block
	}
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
	case Cert:
		f.CertChecked = true
		f.CertUntrusted = e.Untrusted
		if e.Subject != "" {
			f.CertSubject = e.Subject
		}
	case DNS:
		if e.Suspicious {
			f.DNSInjected = true
			f.DNSReason = e.Reason
		}
	}
}

// SetVerdict records an authoritative deep-analysis result for a domain,
// promoting its board badge from the passive guess to the real verdict and
// attaching the reason and the protective action Lumra chose on its own.
func (t *Tracker) SetVerdict(domain string, v *verdict.Verdict, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if f := t.flows[domain]; f != nil {
		f.Analyzed = true
		f.AnalyzedAt = now
		f.DeepType = v.Type
		f.Confidence = v.Confidence
		f.DeepCause = v.Cause
		f.Attribution = v.Attribution
		f.Authority = v.Authority
		f.Action = Recommend(v.Type)
	}
}

// SetEnforced records the summary of an applied enforcement lever for a domain.
func (t *Tracker) SetEnforced(domain, summary string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if f := t.flows[domain]; f != nil {
		f.Enforced = summary
	}
}

// PendingAnalysis returns the domains the Escalator should (re)diagnose now: any
// flow that has shown a connection outcome and either has never been analyzed or
// was last analyzed longer ago than reanalyze. Pure selection over current state.
func (t *Tracker) PendingAnalysis(reanalyze time.Duration, now time.Time) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for name, f := range t.flows {
		if !f.Handshake && f.Resets == 0 && !f.DNSInjected {
			continue // nothing has happened yet; wait for an outcome
		}
		if !f.Analyzed || now.Sub(f.AnalyzedAt) >= reanalyze {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
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
