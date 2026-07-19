package live

import (
	"context"
	"sync"
	"time"

	"github.com/croc100/lumra/internal/verdict"
)

// Diagnoser runs a full active diagnosis for one domain. engine.Diagnose
// satisfies it; tests inject a fake.
type Diagnoser func(ctx context.Context, domain string) *verdict.Verdict

// Escalator is what makes the cockpit automatic. The passive tap only ever sees
// metadata, so a domain's badge starts as a guess. The Escalator watches the
// board and, on its own, runs a full active diagnosis for any domain with an
// outcome, writing the authoritative verdict back so the badge resolves itself.
// The user never selects or drills — they just watch the board settle.
type Escalator struct {
	tracker  *Tracker
	diagnose Diagnoser

	// Interval is how often the board is swept for domains needing analysis.
	Interval time.Duration
	// Reanalyze is how long an authoritative verdict is trusted before a domain
	// is diagnosed again (so a state change is eventually picked up).
	Reanalyze time.Duration
	// Concurrency bounds simultaneous active diagnoses so the sweep cannot flood
	// the network with probe traffic.
	Concurrency int
	// PerDiagnosis bounds one diagnosis so a hung probe cannot wedge a worker.
	PerDiagnosis time.Duration
}

// NewEscalator builds an Escalator with sensible defaults for interactive use.
func NewEscalator(t *Tracker, d Diagnoser) *Escalator {
	return &Escalator{
		tracker:      t,
		diagnose:     d,
		Interval:     2 * time.Second,
		Reanalyze:    2 * time.Minute,
		Concurrency:  3,
		PerDiagnosis: 20 * time.Second,
	}
}

// Run sweeps the board until ctx is cancelled, diagnosing pending domains in the
// background and folding results back into the tracker.
func (e *Escalator) Run(ctx context.Context) {
	sem := make(chan struct{}, e.Concurrency)
	var inFlight sync.Map // domain -> struct{}, so a slow diagnosis is not re-queued
	var wg sync.WaitGroup

	t := time.NewTicker(e.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-t.C:
		}
		for _, domain := range e.tracker.PendingAnalysis(e.Reanalyze, time.Now()) {
			if _, busy := inFlight.LoadOrStore(domain, struct{}{}); busy {
				continue
			}
			wg.Add(1)
			go func(d string) {
				defer wg.Done()
				defer inFlight.Delete(d)
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()
				e.analyze(ctx, d)
			}(domain)
		}
	}
}

// analyze runs one bounded diagnosis and records its verdict.
func (e *Escalator) analyze(ctx context.Context, domain string) {
	dctx, cancel := context.WithTimeout(ctx, e.PerDiagnosis)
	defer cancel()
	v := e.diagnose(dctx, domain)
	if v == nil {
		return
	}
	e.tracker.SetVerdict(domain, v, time.Now())
}
