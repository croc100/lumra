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
		fmt.Fprintf(&b, "  %s  %-28s %-7s %s\n",
			badge(f.Nature()), truncate(f.Domain, 28), versionLabel(f.Version), statusNote(f))
		// Auto drill-down: once analyzed, the reason and the protective action
		// Lumra took surface on their own — the user never has to select a row.
		if f.Analyzed && f.Nature() != verdict.NatureNone {
			if f.DeepCause != "" {
				fmt.Fprintf(&b, "        └ why: %s\n", truncate(oneLine(f.DeepCause), 66))
			}
			if lbl := f.Action.Label(); lbl != "" {
				fmt.Fprintf(&b, "        └ %s\n", lbl)
			}
		}
	}
	return b.String()
}

// statusNote is the human-readable tail of a board row. Once a domain has been
// analyzed, it states the authoritative verdict; before that it reports only
// what the passive tap has proven.
func statusNote(f Flow) string {
	if f.Analyzed {
		switch f.Nature() {
		case verdict.NatureNone:
			return "clean"
		default:
			if f.Confidence != "" {
				return fmt.Sprintf("%s (%s confidence)", f.DeepType, f.Confidence)
			}
			return string(f.DeepType)
		}
	}
	switch f.Nature() {
	case verdict.NatureControl:
		return fmt.Sprintf("BLOCKED — %d reset(s), no session established", f.Resets)
	case verdict.NatureNone:
		return "handshake OK — analyzing…"
	default:
		return fmt.Sprintf("%d attempt(s), awaiting handshake", f.Hits)
	}
}

// oneLine collapses internal whitespace/newlines so a multi-sentence cause fits
// on a single board row.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// truncate shortens s to n runes with an ellipsis so long domains keep columns aligned.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
