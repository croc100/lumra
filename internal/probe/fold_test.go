package probe

import (
	"testing"

	"github.com/croc100/lumra/internal/verdict"
)

// contributor is the shared shape every probe finding implements. The engine
// folds a sequence of these into one verdict; these tests pin the precedence.
type contributor interface {
	Contribute(*verdict.Verdict)
}

// fold replays contributors in engine order (see engine.Diagnose): DNS, then the
// target-IP probes (TLS, RST, throttle), then the self-identifying block page,
// and finally control — which is applied last so a dead local network overrides
// any target-specific finding.
func fold(cs ...contributor) *verdict.Verdict {
	v := &verdict.Verdict{Target: "t", Type: verdict.OK, Confidence: verdict.Low}
	for _, c := range cs {
		c.Contribute(v)
	}
	return v
}

// Healthy building blocks each probe agrees are clean.
func cleanDNS() *DNSFinding {
	return &DNSFinding{Domain: "t", GroundTruth: []string{"93.184.216.34"}}
}
func cleanTLS() *TLSFinding {
	return &TLSFinding{Domain: "t", IP: "93.184.216.34", Target: tlsAttempt{Connected: true, HandshakeOK: true}}
}
func cleanRST() *RSTFinding { return &RSTFinding{Available: false, Note: "unprivileged"} }
func cleanRate() *ThrottleFinding {
	return &ThrottleFinding{Measured: true, Throttled: false, Note: "healthy"}
}
func upControl() *ControlFinding { return &ControlFinding{Reachable: true, Reached: "1.1.1.1:443"} }

func TestFoldPrecedence(t *testing.T) {
	tests := []struct {
		name     string
		findings []contributor
		wantType verdict.Type
		wantConf verdict.Confidence
		wantAttr verdict.Attribution
		wantAuth string
	}{
		{
			name:     "all clean stays OK",
			findings: []contributor{cleanDNS(), cleanTLS(), cleanRST(), cleanRate(), upControl()},
			wantType: verdict.OK, wantConf: verdict.Low,
		},
		{
			name: "dns tampering with a live line",
			findings: []contributor{
				&DNSFinding{Domain: "t", Tampered: true, Reason: reasonBogon, Confidence: verdict.High, Suspicious: []string{"10.10.10.10"}, GroundTruth: []string{"93.184.216.34"}},
				cleanTLS(), cleanRST(), cleanRate(), upControl(),
			},
			wantType: verdict.DNSTampering, wantConf: verdict.High,
		},
		{
			name: "sni filtering outranks a coincident throttle reading",
			findings: []contributor{
				cleanDNS(),
				&TLSFinding{Domain: "t", IP: "93.184.216.34", Target: tlsAttempt{Connected: true, Reset: true}, Benign: tlsAttempt{Connected: true, HandshakeOK: true}},
				cleanRST(),
				&ThrottleFinding{Measured: true, Throttled: true, Note: "selective"},
				upControl(),
			},
			wantType: verdict.SNIFiltering, wantConf: verdict.High,
		},
		{
			name: "tls mitm from a substituted certificate",
			findings: []contributor{
				cleanDNS(),
				&TLSFinding{Domain: "t", IP: "93.184.216.34", Target: tlsAttempt{Connected: true, HandshakeOK: true, CertUntrusted: true, CertSubject: "proxy"}, Benign: tlsAttempt{Connected: true, HandshakeOK: true}},
				cleanRST(), cleanRate(), upControl(),
			},
			wantType: verdict.TLSMITM, wantConf: verdict.Medium,
		},
		{
			name: "ip-level block: reset on every sni",
			findings: []contributor{
				cleanDNS(),
				&TLSFinding{Domain: "t", IP: "93.184.216.34", Target: tlsAttempt{Connected: true, Reset: true}, Benign: tlsAttempt{Connected: true, Reset: true}},
				cleanRST(), cleanRate(), upControl(),
			},
			wantType: verdict.IPBlocking, wantConf: verdict.Medium,
		},
		{
			name: "throttling wins only when nothing stronger fired",
			findings: []contributor{
				cleanDNS(), cleanTLS(), cleanRST(),
				&ThrottleFinding{Measured: true, Throttled: true, Note: "selective"},
				upControl(),
			},
			wantType: verdict.Throttling, wantConf: verdict.Medium, wantAttr: verdict.AttrInNetwork,
		},
		{
			name: "block page names the operator but keeps the stronger type",
			findings: []contributor{
				cleanDNS(),
				&TLSFinding{Domain: "t", IP: "93.184.216.34", Target: tlsAttempt{Connected: true, Reset: true}, Benign: tlsAttempt{Connected: true, HandshakeOK: true}},
				cleanRST(), cleanRate(),
				&BlockPageFinding{Authority: "KCSC", Matched: "warning.or.kr", Country: "KR"},
				upControl(),
			},
			wantType: verdict.SNIFiltering, wantConf: verdict.High,
			wantAttr: verdict.AttrSelfIdentified, wantAuth: "KCSC",
		},
		{
			name: "dead local network overrides every target finding",
			findings: []contributor{
				&DNSFinding{Domain: "t", Tampered: true, Reason: reasonBogon, Confidence: verdict.High, Suspicious: []string{"10.10.10.10"}, GroundTruth: []string{"93.184.216.34"}},
				cleanTLS(), cleanRST(),
				&ThrottleFinding{Measured: true, Throttled: true, Note: "selective"},
				&BlockPageFinding{Authority: "KCSC", Matched: "warning.or.kr"},
				&ControlFinding{Reachable: false},
			},
			wantType: verdict.LocalIssue, wantConf: verdict.High, wantAttr: verdict.AttrLocal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := fold(tt.findings...)
			if v.Type != tt.wantType {
				t.Errorf("Type = %s, want %s", v.Type, tt.wantType)
			}
			if v.Confidence != tt.wantConf {
				t.Errorf("Confidence = %s, want %s", v.Confidence, tt.wantConf)
			}
			if tt.wantAttr != "" && v.Attribution != tt.wantAttr {
				t.Errorf("Attribution = %q, want %q", v.Attribution, tt.wantAttr)
			}
			if tt.wantAuth != "" && v.Authority != tt.wantAuth {
				t.Errorf("Authority = %q, want %q", v.Authority, tt.wantAuth)
			}
		})
	}
}
