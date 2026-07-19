// Package watch turns Lumra's one-shot diagnosis into continuous monitoring:
// it polls a target on an interval and emits an event only when the
// interference state changes, building a "blocked at HH:MM" timeline. It is the
// seed of the P2 SaaS monitoring product.
package watch

import (
	"context"
	"time"

	"github.com/croc100/lumra/internal/verdict"
)

// Diagnoser runs one diagnosis. engine.Diagnose satisfies it; tests inject a fake.
type Diagnoser func(ctx context.Context, target string) *verdict.Verdict

// EventKind marks how the monitored state moved.
type EventKind string

const (
	// Start is the first observation; it establishes the baseline.
	Start EventKind = "start"
	// Blocked is a transition from a clean/OK state into any interference.
	Blocked EventKind = "blocked"
	// Recovered is a transition from interference back to OK.
	Recovered EventKind = "recovered"
	// Changed is a transition between two different interference types.
	Changed EventKind = "changed"
)

// Event is one point on the timeline: a state transition observed at a time.
type Event struct {
	At      time.Time        `json:"at"`
	Kind    EventKind        `json:"kind"`
	Target  string           `json:"target"`
	Type    verdict.Type     `json:"type"`
	Prev    verdict.Type     `json:"prev,omitempty"`
	Verdict *verdict.Verdict `json:"verdict"`
}

// classify decides the event kind for a transition from prev to cur. It returns
// ok=false when nothing meaningful changed (same type as last observation).
func classify(prev, cur verdict.Type, first bool) (EventKind, bool) {
	if first {
		return Start, true
	}
	if prev == cur {
		return "", false
	}
	switch {
	case cur == verdict.OK:
		return Recovered, true
	case prev == verdict.OK:
		return Blocked, true
	default:
		return Changed, true
	}
}

// Monitor holds the running state of one watched target. It is not safe for
// concurrent use; a single Run goroutine owns it.
type Monitor struct {
	Target   string
	diagnose Diagnoser
	prev     verdict.Type
	started  bool
}

// New builds a Monitor for target using the given Diagnoser.
func New(target string, d Diagnoser) *Monitor {
	return &Monitor{Target: target, diagnose: d}
}

// Poll runs one diagnosis and returns an Event when the state changed, or
// ok=false when it held steady. now is injected so callers control timestamps.
func (m *Monitor) Poll(ctx context.Context, now time.Time) (Event, bool) {
	v := m.diagnose(ctx, m.Target)
	prev := m.prev
	first := !m.started
	kind, ok := classify(prev, v.Type, first)
	m.prev = v.Type
	m.started = true
	if !ok {
		return Event{}, false
	}
	ev := Event{At: now, Kind: kind, Target: m.Target, Type: v.Type, Verdict: v}
	if kind != Start {
		ev.Prev = prev
	}
	return ev, true
}

// Run polls target every interval until ctx is cancelled, delivering each state
// change to emit. It fires an immediate first poll so the baseline appears at
// once rather than after one interval.
func (m *Monitor) Run(ctx context.Context, interval time.Duration, emit func(Event)) {
	if ev, ok := m.Poll(ctx, time.Now()); ok {
		emit(ev)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if ev, ok := m.Poll(ctx, now); ok {
				emit(ev)
			}
		}
	}
}
