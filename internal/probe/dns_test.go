package probe

import (
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/croc100/lumra/internal/verdict"
)

func TestIsSuspicious(t *testing.T) {
	cases := map[string]bool{
		"93.184.216.34": false, // real public IP
		"1.1.1.1":       false,
		"127.0.0.1":     true, // loopback sink
		"10.0.0.1":      true, // private
		"0.0.0.0":       true, // unspecified
		"169.254.1.1":   true, // link-local
		"not-an-ip":     true,
	}
	for ip, want := range cases {
		if got := isSuspicious(ip); got != want {
			t.Errorf("isSuspicious(%q) = %v, want %v", ip, got, want)
		}
	}
}

// A plaintext resolver returning a loopback sink outside the DoH ground truth
// must be flagged as tampering with high confidence.
func TestContributeTampered(t *testing.T) {
	f := &DNSFinding{
		Domain:      "blocked.example",
		GroundTruth: []string{"93.184.216.34"},
		Tampered:    true,
		Reason:      reasonBogon,
		Confidence:  verdict.High,
		Suspicious:  []string{"127.0.0.1"},
	}
	v := &verdict.Verdict{Target: "blocked.example", Type: verdict.OK}
	f.Contribute(v)

	if v.Type != verdict.DNSTampering {
		t.Fatalf("Type = %v, want DNS_TAMPERING", v.Type)
	}
	if v.Confidence != verdict.High {
		t.Errorf("Confidence = %v, want high", v.Confidence)
	}
	if len(v.Evidence) != 1 || v.Evidence[0].Outcome != verdict.Fail {
		t.Errorf("expected one Fail evidence, got %+v", v.Evidence)
	}
}

// Consistent answers with a valid ground truth must read as clean.
func TestContributeClean(t *testing.T) {
	f := &DNSFinding{
		Domain:      "ok.example",
		GroundTruth: []string{"93.184.216.34"},
		Tampered:    false,
	}
	v := &verdict.Verdict{Target: "ok.example", Type: verdict.OK}
	f.Contribute(v)

	if v.Type != verdict.OK {
		t.Fatalf("Type = %v, want OK", v.Type)
	}
	if len(v.Evidence) != 1 || v.Evidence[0].Outcome != verdict.Pass {
		t.Errorf("expected one Pass evidence, got %+v", v.Evidence)
	}
}

// assess is the pure classifier — pin every injection signature and the
// deliberate non-conclusions (public divergence, no ground truth).
func TestAssess(t *testing.T) {
	tests := []struct {
		name       string
		f          DNSFinding
		wantTamper bool
		wantReason dnsReason
		wantPublic int // len(DivergentPublic)
	}{
		{
			name: "bogon injection",
			f: DNSFinding{
				GroundTruth: []string{"93.184.216.34"},
				Answers:     map[string][]string{"public-google": {"127.0.0.1"}},
			},
			wantTamper: true, wantReason: reasonBogon,
		},
		{
			name: "nxdomain injection",
			f: DNSFinding{
				GroundTruth: []string{"93.184.216.34"},
				NotFound:    map[string]bool{"public-google": true},
			},
			wantTamper: true, wantReason: reasonNXDOMAIN,
		},
		{
			name: "duplicate-response injection overrides reason",
			f: DNSFinding{
				GroundTruth: []string{"93.184.216.34"},
				Answers:     map[string][]string{"public-google": {"127.0.0.1"}},
				Duplicated:  true,
			},
			wantTamper: true, wantReason: reasonDuplicate,
		},
		{
			name: "public divergence is not tampering",
			f: DNSFinding{
				GroundTruth: []string{"93.184.216.34"},
				Answers:     map[string][]string{"public-google": {"203.0.113.9"}},
			},
			wantTamper: false, wantReason: reasonNone, wantPublic: 1,
		},
		{
			name: "clean: matches ground truth",
			f: DNSFinding{
				GroundTruth: []string{"93.184.216.34"},
				Answers:     map[string][]string{"public-google": {"93.184.216.34"}},
			},
			wantTamper: false, wantReason: reasonNone,
		},
		{
			name: "no ground truth: cannot conclude even on a bogon",
			f: DNSFinding{
				Answers: map[string][]string{"public-google": {"127.0.0.1"}},
			},
			wantTamper: false, wantReason: reasonNone,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.f
			if f.NotFound == nil {
				f.NotFound = map[string]bool{}
			}
			f.assess()
			if f.Tampered != tt.wantTamper {
				t.Errorf("Tampered = %v, want %v", f.Tampered, tt.wantTamper)
			}
			if f.Reason != tt.wantReason {
				t.Errorf("Reason = %q, want %q", f.Reason, tt.wantReason)
			}
			if len(f.DivergentPublic) != tt.wantPublic {
				t.Errorf("DivergentPublic = %v, want %d", f.DivergentPublic, tt.wantPublic)
			}
			if tt.wantTamper && f.Confidence != verdict.High {
				t.Errorf("Confidence = %q, want high for a tampering verdict", f.Confidence)
			}
		})
	}
}

// aResponse packs a DNS A-record response for testing the wire parser.
func aResponse(id uint16, name string, ips ...string) []byte {
	n, _ := dnsmessage.NewName(fqdn(name))
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, Response: true},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	for _, ip := range ips {
		var a [4]byte
		copy(a[:], net.ParseIP(ip).To4())
		msg.Answers = append(msg.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			Body:   &dnsmessage.AResource{A: a},
		})
	}
	b, _ := msg.Pack()
	return b
}

func TestParseAAnswers(t *testing.T) {
	const id = 0x1234
	ips, ok := parseAAnswers(aResponse(id, "x.example", "1.2.3.4", "5.6.7.8"), id)
	if !ok {
		t.Fatal("ok=false for a valid response")
	}
	if len(ips) != 2 || ips[0] != "1.2.3.4" || ips[1] != "5.6.7.8" {
		t.Errorf("ips = %v, want [1.2.3.4 5.6.7.8]", ips)
	}
	// A mismatched transaction ID must be rejected (stray packet).
	if _, ok := parseAAnswers(aResponse(id, "x.example", "1.2.3.4"), id+1); ok {
		t.Error("mismatched ID accepted")
	}
	// Garbage must be rejected, never guessed.
	if _, ok := parseAAnswers([]byte{0, 1, 2}, id); ok {
		t.Error("garbage accepted")
	}
}

func TestDistinctAnswerSets(t *testing.T) {
	const id = 0x7777
	real := aResponse(id, "t.example", "93.184.216.34")
	forged := aResponse(id, "t.example", "10.10.10.10")

	// A forged answer racing the real one → two distinct sets → injection.
	if got := distinctAnswerSets([][]byte{forged, real}, id); len(got) != 2 {
		t.Errorf("distinct sets = %d, want 2", len(got))
	}
	// The same answer twice (retransmit) is one set, not an injection.
	if got := distinctAnswerSets([][]byte{real, real}, id); len(got) != 1 {
		t.Errorf("distinct sets = %d, want 1", len(got))
	}
	// Responses for another query id are ignored.
	if got := distinctAnswerSets([][]byte{aResponse(id+9, "t.example", "1.1.1.1")}, id); len(got) != 0 {
		t.Errorf("distinct sets = %d, want 0", len(got))
	}
}
