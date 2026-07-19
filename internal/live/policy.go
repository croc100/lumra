package live

import "github.com/croc100/lumra/internal/verdict"

// Action is the protective measure Lumra applies to a domain on its own once it
// has diagnosed interference — the automatic control lever. It is deliberately a
// declarative policy, not an in-path intervention: Lumra is a measurement tool,
// so it decides and records the protection the user's stack (or warren) should
// enforce, rather than silently rerouting traffic itself.
type Action string

const (
	ActionNone      Action = ""               // nothing to do (clean, or not fixable here)
	ActionUseDoH    Action = "use-DoH"        // resolve over DoH to defeat DNS tampering
	ActionRequire13 Action = "require-TLS1.3" // pin TLS 1.3 / ECH to blind an interceptor
	ActionCaution   Action = "caution"        // interception detected, no automatic fix — warn
	ActionBlocked   Action = "blocked"        // hard block; access is prevented, flag it
)

// Recommend maps a verdict Type to the protective Action Lumra applies
// automatically. Pure and table-tested. The mapping follows the interference's
// Nature: DNS tampering is defeated by bypassing the poisoned resolver;
// surveillance is blunted by forcing the encrypted-handshake path; hard blocks
// are surfaced, not silently worked around (that is warren's job).
func Recommend(t verdict.Type) Action {
	switch t {
	case verdict.DNSTampering:
		return ActionUseDoH
	case verdict.SNIFiltering, verdict.TLSDowngrade:
		return ActionRequire13
	case verdict.TLSMITM:
		return ActionCaution
	case verdict.RSTInjection, verdict.IPBlocking, verdict.BlockPage:
		return ActionBlocked
	default: // OK, Throttling, faults, inconclusive → no automatic lever
		return ActionNone
	}
}

// Label renders an Action for the board, or "" when there is nothing to show.
func (a Action) Label() string {
	switch a {
	case ActionUseDoH:
		return "auto: resolving over DoH"
	case ActionRequire13:
		return "auto: forcing TLS 1.3 / ECH"
	case ActionCaution:
		return "auto: flagged — interception, do not trust"
	case ActionBlocked:
		return "auto: flagged blocked"
	default:
		return ""
	}
}
