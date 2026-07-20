package probe

import "github.com/croc100/lumra/internal/verdict"

// Repeated-trial robustness is what separates a rigorous censorship measurement
// from a naive one. A middlebox reset is not deterministic: transient congestion
// produces a stray reset (a false positive from a single shot), and load-based or
// "residual" censorship resets only a fraction of connections (a false negative a
// single shot misses entirely). Lumra therefore repeats each reset-sensitive
// handshake and reasons about the *rate*, not one outcome.
//
// The classification is pure and table-tested; the network sampling lives in the
// probe that calls it.

// tlsTrials is how many times each SNI arm is attempted. Small enough to stay
// within the diagnosis budget, large enough to separate a lone transient reset
// (1/N, treated as noise) from a consistent or clearly intermittent block.
const tlsTrials = 3

// resetPattern is the shape of a reset signal across repeated trials.
type resetPattern string

const (
	patternNone         resetPattern = "none"         // no resets — clean
	patternNoise        resetPattern = "noise"        // a single stray reset — not asserted
	patternIntermittent resetPattern = "intermittent" // some-but-not-all reset — probabilistic block
	patternConsistent   resetPattern = "consistent"   // every trial reset — a deterministic block
)

// classifyResetPattern folds a reset count over n trials into a pattern. A lone
// reset (1 of n, n>=3) is deliberately treated as noise so a single transient RST
// never over-claims a block — the core false-positive guard. When n < 3 there is
// no room to tell noise from signal, so any reset short of all is left unasserted.
func classifyResetPattern(resets, n int) resetPattern {
	switch {
	case n == 0 || resets == 0:
		return patternNone
	case resets == n:
		return patternConsistent
	case n >= 3 && resets == 1:
		return patternNoise
	case n >= 3 && resets >= 2:
		return patternIntermittent
	default:
		// n < 3 with a partial reset: not enough evidence to characterise.
		return patternNoise
	}
}

// patternConfidence maps a reset pattern to the confidence a block verdict built
// on it should carry. A deterministic block is stated with High confidence; a
// probabilistic one is real but weaker, so Medium.
func patternConfidence(p resetPattern) verdict.Confidence {
	switch p {
	case patternConsistent:
		return verdict.High
	case patternIntermittent:
		return verdict.Medium
	default:
		return verdict.Low
	}
}
