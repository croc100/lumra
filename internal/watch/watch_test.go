package watch

import (
	"context"
	"testing"
	"time"

	"github.com/croc100/lumra/internal/verdict"
)

// scriptedDiagnoser returns the next verdict type from a fixed script on each call.
func scriptedDiagnoser(types []verdict.Type) (Diagnoser, *int) {
	i := 0
	d := func(ctx context.Context, target string) *verdict.Verdict {
		t := types[i]
		if i < len(types)-1 {
			i++
		}
		return &verdict.Verdict{Target: target, Type: t}
	}
	return d, &i
}

func TestPollEmitsOnlyOnTransition(t *testing.T) {
	types := []verdict.Type{
		verdict.OK,           // start baseline
		verdict.OK,           // steady, no event
		verdict.DNSTampering, // blocked
		verdict.DNSTampering, // steady
		verdict.SNIFiltering, // changed
		verdict.OK,           // recovered
	}
	d, _ := scriptedDiagnoser(types)
	m := New("example.com", d)

	want := []struct {
		emit bool
		kind EventKind
		prev verdict.Type
	}{
		{true, Start, ""},
		{false, "", ""},
		{true, Blocked, verdict.OK},
		{false, "", ""},
		{true, Changed, verdict.DNSTampering},
		{true, Recovered, verdict.SNIFiltering},
	}

	now := time.Unix(0, 0)
	for step, w := range want {
		ev, ok := m.Poll(context.Background(), now.Add(time.Duration(step)*time.Second))
		if ok != w.emit {
			t.Fatalf("step %d: emit=%v want %v", step, ok, w.emit)
		}
		if !ok {
			continue
		}
		if ev.Kind != w.kind {
			t.Errorf("step %d: kind=%s want %s", step, ev.Kind, w.kind)
		}
		if ev.Prev != w.prev {
			t.Errorf("step %d: prev=%q want %q", step, ev.Prev, w.prev)
		}
	}
}

func TestRunFiresImmediateBaseline(t *testing.T) {
	d, _ := scriptedDiagnoser([]verdict.Type{verdict.OK})
	m := New("x", d)
	ctx, cancel := context.WithCancel(context.Background())

	got := make(chan Event, 1)
	go m.Run(ctx, time.Hour, func(e Event) { got <- e })

	select {
	case ev := <-got:
		if ev.Kind != Start {
			t.Fatalf("first event kind=%s want start", ev.Kind)
		}
	case <-time.After(time.Second):
		t.Fatal("no immediate baseline event")
	}
	cancel()
}
