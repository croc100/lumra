package probe

import (
	"crypto/x509"
	"fmt"
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

// Both SNIs reset → not SNI-specific → IP-level block.
func TestContributeBothReset(t *testing.T) {
	f := &TLSFinding{
		Domain: "blocked.example",
		IP:     "93.184.216.34",
		Target: tlsAttempt{Connected: true, Reset: true},
		Benign: tlsAttempt{Connected: true, Reset: true},
	}
	v := &verdict.Verdict{Target: f.Domain, Type: verdict.OK}
	f.Contribute(v)

	if v.Type != verdict.IPBlocking {
		t.Fatalf("Type = %v, want IP_BLOCKING", v.Type)
	}
	if v.Confidence != verdict.Medium {
		t.Errorf("Confidence = %v, want medium", v.Confidence)
	}
	if len(v.Evidence) != 1 || v.Evidence[0].Outcome != verdict.Fail {
		t.Errorf("expected one Fail evidence, got %+v", v.Evidence)
	}
}

// Handshake completes but the cert does not chain to a trusted root → MITM.
func TestContributeTLSMITM(t *testing.T) {
	f := &TLSFinding{
		Domain: "mitm.example",
		IP:     "93.184.216.34",
		Target: tlsAttempt{Connected: true, HandshakeOK: true, CertUntrusted: true, CertSubject: "evil-proxy"},
		Benign: tlsAttempt{Connected: true, HandshakeOK: true},
	}
	v := &verdict.Verdict{Target: f.Domain, Type: verdict.OK}
	f.Contribute(v)

	if v.Type != verdict.TLSMITM {
		t.Fatalf("Type = %v, want TLS_MITM", v.Type)
	}
	if v.Confidence != verdict.Medium || v.Evidence[0].Outcome != verdict.Fail {
		t.Errorf("want medium/fail, got %v / %+v", v.Confidence, v.Evidence[0])
	}
}

// An expired or wrong-host cert is ordinary — never reported as MITM.
func TestContributeExpiredCertNotMITM(t *testing.T) {
	f := &TLSFinding{
		Domain: "expired.example",
		IP:     "93.184.216.34",
		Target: tlsAttempt{Connected: true, HandshakeOK: true, CertExpired: true},
		Benign: tlsAttempt{Connected: true, HandshakeOK: true},
	}
	v := &verdict.Verdict{Target: f.Domain, Type: verdict.OK}
	f.Contribute(v)

	if v.Type != verdict.OK {
		t.Fatalf("expired cert produced %v, want OK (handshake completed)", v.Type)
	}
}

// Silent blackhole on both arms → Inconclusive (single vantage can't split
// IP block from outage), never an over-claimed block.
func TestContributeBlackhole(t *testing.T) {
	f := &TLSFinding{
		Domain: "dark.example",
		IP:     "203.0.113.9",
		Target: tlsAttempt{Timeout: true},
		Benign: tlsAttempt{Timeout: true},
	}
	v := &verdict.Verdict{Target: f.Domain, Type: verdict.OK}
	f.Contribute(v)

	if v.Type != verdict.Inconclusive {
		t.Fatalf("Type = %v, want INCONCLUSIVE", v.Type)
	}
	if v.Confidence != verdict.Low {
		t.Errorf("Confidence = %v, want low", v.Confidence)
	}
}

func TestClassifyReachability(t *testing.T) {
	conn := func(reset, connected bool) tlsAttempt { return tlsAttempt{Connected: connected, Reset: reset} }
	tests := []struct {
		name           string
		target, benign tlsAttempt
		wantType       verdict.Type
	}{
		{"both reset", conn(true, true), conn(true, true), verdict.IPBlocking},
		{"both dropped", conn(false, false), conn(false, false), verdict.Inconclusive},
		{"target reset only", conn(true, true), conn(false, true), ""},
		{"one dropped one connected", conn(false, false), conn(false, true), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := classifyReachability(tt.target, tt.benign)
			if got != tt.wantType {
				t.Errorf("classifyReachability = %q, want %q", got, tt.wantType)
			}
		})
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

func TestClassifyCert(t *testing.T) {
	untrusted, expired, hostErr := classifyCert(nil)
	if untrusted || expired || hostErr {
		t.Error("nil error should classify as clean")
	}
	if u, _, _ := classifyCert(x509.UnknownAuthorityError{}); !u {
		t.Error("UnknownAuthorityError should be untrusted (MITM signal)")
	}
	if _, _, h := classifyCert(x509.HostnameError{}); !h {
		t.Error("HostnameError should set hostErr")
	}
	if _, e, _ := classifyCert(x509.CertificateInvalidError{Reason: x509.Expired}); !e {
		t.Error("expired cert should set expired")
	}
	// Wrapped errors must still be detected.
	wrapped := fmt.Errorf("verify: %w", x509.UnknownAuthorityError{})
	if u, _, _ := classifyCert(wrapped); !u {
		t.Error("wrapped UnknownAuthorityError should still be untrusted")
	}
	// Expired must never be mistaken for the substitution (untrusted) signal.
	if u, _, _ := classifyCert(x509.CertificateInvalidError{Reason: x509.Expired}); u {
		t.Error("expired cert must not be flagged untrusted/MITM")
	}
}
