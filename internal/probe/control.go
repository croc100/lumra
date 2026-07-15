package probe

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/croc100/lumra/internal/verdict"
)

// controlAnchors are globally anycast services that are effectively impossible
// to fully block without breaking the internet. If none are reachable on :443,
// the user's own network is down — any target interference we saw is not
// attributable to censorship of that target.
var controlAnchors = []string{
	"1.1.1.1:443", // Cloudflare
	"8.8.8.8:443", // Google
	"9.9.9.9:443", // Quad9
}

// ControlFinding records whether the baseline internet is reachable at all.
type ControlFinding struct {
	Reachable bool
	Reached   string // first anchor that answered
}

// Control tests baseline connectivity against anycast anchors so a local outage
// is never misreported as target censorship.
func Control(ctx context.Context) *ControlFinding {
	f := &ControlFinding{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, anchor := range controlAnchors {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			d := net.Dialer{Timeout: 4 * time.Second}
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				return
			}
			conn.Close()
			mu.Lock()
			if !f.Reachable {
				f.Reachable = true
				f.Reached = addr
			}
			mu.Unlock()
		}(anchor)
	}
	wg.Wait()
	return f
}

// Contribute finalizes the verdict against baseline connectivity. If the control
// anchors are unreachable, the user's network is at fault and this overrides any
// target-specific finding. Call this last.
func (f *ControlFinding) Contribute(v *verdict.Verdict) {
	if f.Reachable {
		v.Add("CTRL", verdict.Pass, "baseline reachable via "+f.Reached+" (not a local issue)")
		return
	}
	v.Add("CTRL", verdict.Fail, "no anycast anchor reachable on :443 — local network is down")
	v.Type = verdict.LocalIssue
	v.Confidence = verdict.High
	v.Attribution = verdict.AttrLocal
	v.Cause = "None of the global control anchors are reachable, so the failure is " +
		"in your own network — not interference with the target."
}
