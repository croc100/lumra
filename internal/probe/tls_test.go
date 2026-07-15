package probe

import (
	"testing"

	"github.com/croc100/lumra/internal/verdict"
)

// Target SNI reset while benign SNI is accepted on the same IP → SNI filtering.
func TestContributeSNIFiltering(t *testing.T) {
	f := &TLSFinding{
		Domain: "blocked.example",
		IP:     "93.184.216.34",
		Target: tlsAttempt{SNI: "blocked.example", Connected: true, Reset: true},
		Benign: tlsAttempt{SNI: benignSNI, Connected: true, HandshakeOK: true},
	}
	v := &verdict.Verdict{Target: f.Domain, Type: verdict.OK}
	f.Contribute(v)

	if v.Type != verdict.SNIFiltering {
		t.Fatalf("Type = %v, want SNI_FILTERING", v.Type)
	}
	if v.Confidence != verdict.High {
		t.Errorf("Confidence = %v, want high", v.Confidence)
	}
	if len(v.Evidence) != 1 || v.Evidence[0].Outcome != verdict.Fail {
		t.Errorf("expected one Fail evidence, got %+v", v.Evidence)
	}
}

// Both SNIs reset → not SNI-specific; leave verdict for the RST/IP probe.
func TestContributeBothReset(t *testing.T) {
	f := &TLSFinding{
		Domain: "blocked.example",
		IP:     "93.184.216.34",
		Target: tlsAttempt{Connected: true, Reset: true},
		Benign: tlsAttempt{Connected: true, Reset: true},
	}
	v := &verdict.Verdict{Target: f.Domain, Type: verdict.OK}
	f.Contribute(v)

	if v.Type != verdict.OK {
		t.Fatalf("Type = %v, want OK (deferred)", v.Type)
	}
	if len(v.Evidence) != 1 || v.Evidence[0].Outcome != verdict.Info {
		t.Errorf("expected one Info evidence, got %+v", v.Evidence)
	}
}

// Clean handshake with the target SNI → pass.
func TestContributeTLSClean(t *testing.T) {
	f := &TLSFinding{
		Domain: "ok.example",
		IP:     "93.184.216.34",
		Target: tlsAttempt{Connected: true, HandshakeOK: true},
		Benign: tlsAttempt{Connected: true, HandshakeOK: true},
	}
	v := &verdict.Verdict{Target: f.Domain, Type: verdict.OK}
	f.Contribute(v)

	if v.Type != verdict.OK {
		t.Fatalf("Type = %v, want OK", v.Type)
	}
	if len(v.Evidence) != 1 || v.Evidence[0].Outcome != verdict.Pass {
		t.Errorf("expected one Pass evidence, got %+v", v.Evidence)
	}
}
