//go:build !linux

package probe

import (
	"context"
	"runtime"
)

// captureRST degrades on platforms without the raw-socket backend. Rather than
// guess, it reports that attribution was not measured — the honest default.
func captureRST(_ context.Context, _ string) *RSTFinding {
	return &RSTFinding{
		Available: false,
		Note:      "raw RST/TTL capture is implemented for Linux only (this host is " + runtime.GOOS + ")",
	}
}
