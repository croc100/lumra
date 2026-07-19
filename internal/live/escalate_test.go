package live

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croc100/lumra/internal/verdict"
)

func TestPendingAnalysisSelection(t *testing.T) {
	tr := NewTracker()
	now := time.Unix(1000, 0)
	// a.com: handshake → eligible. b.com: only attempts → not yet. c.com: reset → eligible.
	tr.Observe(Event{Kind: ClientHello, Domain: "a.com", At: now})
	tr.Observe(Event{Kind: ServerHello, Domain: "a.com", At: now})
	tr.Observe(Event{Kind: ClientHello, Domain: "b.com", At: now})
	tr.Observe(Event{Kind: Reset, Domain: "c.com", At: now})

	got := tr.PendingAnalysis(time.Minute, now)
	if len(got) != 2 || got[0] != "a.com" || got[1] != "c.com" {
		t.Fatalf("pending = %v, want [a.com c.com]", got)
	}

	// Once analyzed, a.com drops out until the reanalyze window elapses.
	tr.SetVerdict("a.com", &verdict.Verdict{Type: verdict.OK, Confidence: verdict.Low}, now)
	if got := tr.PendingAnalysis(time.Minute, now.Add(30*time.Second)); len(got) != 1 || got[0] != "c.com" {
		t.Fatalf("after analysis pending = %v, want [c.com]", got)
	}
	// After the window, it becomes eligible again.
	if got := tr.PendingAnalysis(time.Minute, now.Add(2*time.Minute)); len(got) != 2 {
		t.Fatalf("after reanalyze window pending = %v, want 2", got)
	}
}

func TestEscalatorPromotesBadge(t *testing.T) {
	tr := NewTracker()
	now := time.Now()
	tr.Observe(Event{Kind: ClientHello, Domain: "watched.example", At: now})
	tr.Observe(Event{Kind: ServerHello, Domain: "watched.example", At: now})

	var calls int32
	diag := func(ctx context.Context, domain string) *verdict.Verdict {
		atomic.AddInt32(&calls, 1)
		return &verdict.Verdict{Target: domain, Type: verdict.TLSMITM, Confidence: verdict.Medium}
	}
	e := NewEscalator(tr, diag)
	e.Interval = 5 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); e.Run(ctx) }()

	// Wait for the badge to resolve to the authoritative surveillance verdict.
	deadline := time.After(2 * time.Second)
	for {
		snap := tr.Snapshot()
		if len(snap) == 1 && snap[0].Analyzed && snap[0].Nature() == verdict.NatureSurveillance {
			break
		}
		select {
		case <-deadline:
			cancel()
			wg.Wait()
			t.Fatalf("badge did not resolve to surveillance; snapshot=%+v", tr.Snapshot())
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	wg.Wait()
	if atomic.LoadInt32(&calls) == 0 {
		t.Fatal("diagnoser was never called")
	}
}
