package probe

import (
	"testing"

	"github.com/croc100/lumra/internal/verdict"
)

func TestClassifyResetPattern(t *testing.T) {
	tests := []struct {
		resets, n int
		want      resetPattern
	}{
		{0, 3, patternNone},         // clean
		{3, 3, patternConsistent},   // every trial reset — deterministic block
		{2, 3, patternIntermittent}, // majority-but-not-all — probabilistic block
		{1, 3, patternNoise},        // lone reset — filtered as noise (FP guard)
		{1, 5, patternNoise},        // still noise at higher n
		{3, 5, patternIntermittent}, // partial at higher n
		{0, 0, patternNone},         // no trials
		{1, 2, patternNoise},        // n<3: not enough to characterise
		{2, 2, patternConsistent},   // all reset even at n=2
	}
	for _, tt := range tests {
		if got := classifyResetPattern(tt.resets, tt.n); got != tt.want {
			t.Errorf("classifyResetPattern(%d,%d) = %q, want %q", tt.resets, tt.n, got, tt.want)
		}
	}
}

func TestPatternConfidence(t *testing.T) {
	if patternConfidence(patternConsistent) != verdict.High {
		t.Error("consistent block should be High")
	}
	if patternConfidence(patternIntermittent) != verdict.Medium {
		t.Error("intermittent block should be Medium")
	}
	if patternConfidence(patternNoise) != verdict.Low {
		t.Error("noise should be Low")
	}
}

func TestSummarizeMajorityVote(t *testing.T) {
	// 2 of 3 reset → representative is a reset; reset count preserved.
	attempts := []tlsAttempt{
		{SNI: "x", Reset: true},
		{SNI: "x", Reset: true},
		{SNI: "x", Connected: true, HandshakeOK: true},
	}
	rep, resets := summarize(attempts)
	if resets != 2 {
		t.Fatalf("resets = %d, want 2", resets)
	}
	if !rep.Reset {
		t.Error("majority reset should make the representative a reset")
	}

	// A lone reset does not flip a mostly-clean representative.
	clean := []tlsAttempt{
		{SNI: "x", Reset: true},
		{SNI: "x", Connected: true, HandshakeOK: true},
		{SNI: "x", Connected: true, HandshakeOK: true},
	}
	rep2, resets2 := summarize(clean)
	if resets2 != 1 {
		t.Fatalf("resets = %d, want 1", resets2)
	}
	if rep2.Reset || !rep2.HandshakeOK {
		t.Error("a single reset should not flip a majority-clean representative")
	}
}

func TestSummarizeCapturesCertFromCompletedTrial(t *testing.T) {
	// Even if one trial reset, cert details from a completed handshake survive so
	// MITM is still detectable.
	attempts := []tlsAttempt{
		{SNI: "x", Reset: true},
		{SNI: "x", Connected: true, HandshakeOK: true, CertUntrusted: true, CertSubject: "evil"},
		{SNI: "x", Connected: true, HandshakeOK: true, CertUntrusted: true, CertSubject: "evil"},
	}
	rep, _ := summarize(attempts)
	if !rep.CertUntrusted || rep.CertSubject != "evil" {
		t.Fatalf("cert substitution detail lost across trials: %+v", rep)
	}
}

// Probabilistic SNI filtering: target resets on 2 of 3 trials, benign clean.
func TestContributeProbabilisticSNIFiltering(t *testing.T) {
	f := &TLSFinding{
		Domain:       "blocked.example",
		IP:           "93.184.216.34",
		Target:       tlsAttempt{Reset: true},
		Benign:       tlsAttempt{Connected: true, HandshakeOK: true},
		TargetTrials: 3, TargetResets: 2,
		BenignTrials: 3, BenignResets: 0,
	}
	v := &verdict.Verdict{Target: f.Domain, Type: verdict.OK}
	f.Contribute(v)

	if v.Type != verdict.SNIFiltering {
		t.Fatalf("Type = %v, want SNI_FILTERING", v.Type)
	}
	if v.Confidence != verdict.Medium {
		t.Errorf("probabilistic filtering should be Medium confidence, got %v", v.Confidence)
	}
}

// A lone transient reset must NOT be asserted as filtering — the false-positive guard.
func TestContributeLoneResetIsNoise(t *testing.T) {
	f := &TLSFinding{
		Domain:       "flaky.example",
		IP:           "93.184.216.34",
		Target:       tlsAttempt{Connected: true, HandshakeOK: true}, // representative clean (2/3 ok)
		Benign:       tlsAttempt{Connected: true, HandshakeOK: true},
		TargetTrials: 3, TargetResets: 1,
		BenignTrials: 3, BenignResets: 0,
	}
	v := &verdict.Verdict{Target: f.Domain, Type: verdict.OK}
	f.Contribute(v)

	if v.Type == verdict.SNIFiltering {
		t.Fatal("a single transient reset must not be asserted as SNI filtering")
	}
	if v.Type != verdict.OK {
		t.Fatalf("Type = %v, want OK (noise filtered)", v.Type)
	}
}

// Consistent reset across all trials → deterministic block, High confidence.
func TestContributeConsistentTrialSNIFiltering(t *testing.T) {
	f := &TLSFinding{
		Domain:       "blocked.example",
		IP:           "93.184.216.34",
		Target:       tlsAttempt{Reset: true},
		Benign:       tlsAttempt{Connected: true, HandshakeOK: true},
		TargetTrials: 3, TargetResets: 3,
		BenignTrials: 3, BenignResets: 0,
	}
	v := &verdict.Verdict{Target: f.Domain, Type: verdict.OK}
	f.Contribute(v)

	if v.Type != verdict.SNIFiltering || v.Confidence != verdict.High {
		t.Fatalf("consistent reset should be High SNI filtering, got %v/%v", v.Type, v.Confidence)
	}
}
