package live

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/croc100/lumra/internal/verdict"
)

func TestTrackerFoldsEvents(t *testing.T) {
	tr := NewTracker()
	base := time.Unix(1000, 0)
	tr.Observe(Event{Kind: ClientHello, Domain: "a.com", At: base})
	tr.Observe(Event{Kind: ServerHello, Domain: "a.com", Version: tls.VersionTLS13, At: base.Add(time.Second)})
	tr.Observe(Event{Kind: ClientHello, Domain: "b.com", At: base.Add(2 * time.Second)})
	tr.Observe(Event{Kind: Reset, Domain: "b.com", At: base.Add(3 * time.Second)})

	snap := tr.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("got %d flows, want 2", len(snap))
	}
	// Most recently active first → b.com (reset at +3s) leads a.com.
	if snap[0].Domain != "b.com" {
		t.Errorf("first flow = %s, want b.com (most recent)", snap[0].Domain)
	}

	byDomain := map[string]Flow{snap[0].Domain: snap[0], snap[1].Domain: snap[1]}
	a := byDomain["a.com"]
	if !a.Handshake || a.Version != tls.VersionTLS13 {
		t.Errorf("a.com: handshake=%v version=%x, want true/1.3", a.Handshake, a.Version)
	}
	if a.Nature() != verdict.NatureNone {
		t.Errorf("a.com nature = %s, want none", a.Nature())
	}
	b := byDomain["b.com"]
	if b.Resets != 1 || b.Handshake {
		t.Errorf("b.com: resets=%d handshake=%v, want 1/false", b.Resets, b.Handshake)
	}
	if b.Nature() != verdict.NatureControl {
		t.Errorf("b.com nature = %s, want control", b.Nature())
	}
}

func TestTrackerEmptyDomainIgnored(t *testing.T) {
	tr := NewTracker()
	tr.Observe(Event{Kind: ClientHello, Domain: "", At: time.Now()})
	if len(tr.Snapshot()) != 0 {
		t.Fatal("empty-domain event should be ignored")
	}
}
