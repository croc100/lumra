package probe

import (
	"testing"

	"github.com/croc100/lumra/internal/verdict"
)

func TestAssessDoH(t *testing.T) {
	tests := []struct {
		name       string
		reachable  int
		total      int
		plaintext  bool
		wantStatus dohStatus
		wantConf   verdict.Confidence
	}{
		{"all healthy", 3, 3, true, dohHealthy, verdict.High},
		{"one blocked, fallback holds", 2, 3, true, dohDegraded, verdict.Medium},
		{"all DoH blocked but plaintext works", 0, 3, true, dohBlocked, verdict.High},
		{"nothing resolves — general outage", 0, 3, false, dohOffline, verdict.Low},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStatus, gotConf := assessDoH(tt.reachable, tt.total, tt.plaintext)
			if gotStatus != tt.wantStatus {
				t.Errorf("status = %q, want %q", gotStatus, tt.wantStatus)
			}
			if gotConf != tt.wantConf {
				t.Errorf("confidence = %q, want %q", gotConf, tt.wantConf)
			}
		})
	}
}

func TestDoHContributeBlocked(t *testing.T) {
	v := &verdict.Verdict{Target: "example.com", Type: verdict.OK}
	f := &DoHFinding{Total: 3, PlaintextOK: true, Status: dohBlocked, Confidence: verdict.High}
	f.Contribute(v)

	if v.Type != verdict.DoHBlocking {
		t.Fatalf("type = %q, want DOH_BLOCKING", v.Type)
	}
	if verdict.NatureOf(v.Type) != verdict.NatureControl {
		t.Fatalf("DoH blocking should fold to control nature")
	}
	if len(v.Evidence) != 1 || v.Evidence[0].Outcome != verdict.Fail {
		t.Fatalf("expected one Fail evidence, got %+v", v.Evidence)
	}
}

func TestDoHContributeDoesNotOverrideStrongerVerdict(t *testing.T) {
	// A confirmed target block must not be downgraded to a channel note.
	v := &verdict.Verdict{Target: "example.com", Type: verdict.RSTInjection, Confidence: verdict.High}
	f := &DoHFinding{Total: 3, PlaintextOK: true, Status: dohBlocked, Confidence: verdict.High}
	f.Contribute(v)

	if v.Type != verdict.RSTInjection {
		t.Fatalf("stronger verdict was overridden: type = %q", v.Type)
	}
	// but the channel attack is still recorded as evidence.
	if len(v.Evidence) != 1 || v.Evidence[0].Probe != "DoH" {
		t.Fatalf("DoH evidence not recorded alongside stronger verdict: %+v", v.Evidence)
	}
}

func TestDoHContributeDegradedIsInfo(t *testing.T) {
	v := &verdict.Verdict{Target: "example.com", Type: verdict.OK}
	f := &DoHFinding{Total: 3, Reachable: []string{"google", "quad9"}, Status: dohDegraded}
	f.Contribute(v)

	if v.Type != verdict.OK {
		t.Fatalf("degraded DoH must not change the verdict type, got %q", v.Type)
	}
	if v.Evidence[0].Outcome != verdict.Info {
		t.Fatalf("degraded DoH should be Info, got %q", v.Evidence[0].Outcome)
	}
}
