package probe

import (
	"context"
	"os"
)

// captureRST is the privilege boundary for RST attribution.
//
// A real implementation opens a raw IPv4 socket (or pcap handle), sends a
// crafted SYN to ip:443, and reads the incoming TCP segments — capturing the
// TTL of both a legitimate SYN/ACK from the destination and any injected RST.
// It requires root / CAP_NET_RAW and, on Linux, suppression of the kernel's own
// RST (e.g. an iptables OUTPUT rule) so the userspace probe owns the flow.
//
// Because that path cannot run unprivileged, this default build degrades: it
// reports that attribution was not measured rather than guessing. The privileged
// capture backend replaces this function (see docs/OVERVIEW.md build order).
func captureRST(_ context.Context, _ string) *RSTFinding {
	if os.Geteuid() != 0 {
		return &RSTFinding{Available: false, Note: "needs raw-socket privilege (run elevated)"}
	}
	// Even when elevated, the raw-capture backend is not yet wired in; report
	// honestly instead of fabricating a measurement.
	return &RSTFinding{Available: false, Note: "raw capture backend not yet implemented"}
}
