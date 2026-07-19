package live

import (
	"fmt"
	"strings"
	"time"

	"github.com/croc100/lumra/internal/verdict"
)

// badge maps a flow's passively-derived nature to a one-glyph status.
func badge(n verdict.Nature) string {
	switch n {
	case verdict.NatureControl:
		return "🚫"
	case verdict.NatureSurveillance:
		return "👁"
	case verdict.NatureDegradation:
		return "🐢"
	case verdict.NatureNone:
		return "✅"
	default:
		return "…"
	}
}

// versionLabel renders a negotiated TLS version compactly for the board.
func versionLabel(v uint16) string {
	switch v {
	case tlsVersion13:
		return "TLS1.3"
	case tlsVersion12:
		return "TLS1.2"
	case tlsVersion11:
		return "TLS1.1"
	case tlsVersion10:
		return "TLS1.0"
	default:
		return "—"
	}
}

// TLS version constants, duplicated here so the renderer does not import
// crypto/tls just for two labels.
const (
	tlsVersion10 = 0x0301
	tlsVersion11 = 0x0302
	tlsVersion12 = 0x0303
	tlsVersion13 = 0x0304
)

// RenderBoard formats the live cockpit: one row per domain, most-recent first,
// each with a status badge, negotiated TLS version, and a short note. It is a
// pure function of the snapshot and the current time, so it is unit-tested and
// the command layer just prints it on a ticker.
func RenderBoard(flows []Flow, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "lumra live — %d domains · %s\n\n", len(flows), now.Format("15:04:05"))
	if len(flows) == 0 {
		b.WriteString("  (waiting for traffic…)\n")
		return b.String()
	}
	for _, f := range flows {
		note := statusNote(f)
		fmt.Fprintf(&b, "  %s  %-28s %-7s %s\n",
			badge(f.Nature()), truncate(f.Domain, 28), versionLabel(f.Version), note)
	}
	return b.String()
}

// statusNote is the human-readable tail of a board row.
func statusNote(f Flow) string {
	switch f.Nature() {
	case verdict.NatureControl:
		return fmt.Sprintf("BLOCKED — %d reset(s), no session established", f.Resets)
	case verdict.NatureNone:
		if f.Resets > 0 {
			return fmt.Sprintf("clean (%d reset(s) seen but session held)", f.Resets)
		}
		return "clean"
	default:
		return fmt.Sprintf("%d attempt(s), awaiting handshake", f.Hits)
	}
}

// truncate shortens s to n runes with an ellipsis so long domains keep columns aligned.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
