package probe

import (
	"testing"

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
