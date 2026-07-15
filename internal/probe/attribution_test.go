package probe

import (
	"testing"

	"github.com/croc100/lumra/internal/verdict"
)

func TestHopsAway(t *testing.T) {
	cases := map[uint8]int{
		54:  10,  // Linux server, initial 64
		118: 10,  // Windows server, initial 128
		250: 5,   // appliance, initial 255
		64:  0,   // right next to us
	}
	for ttl, want := range cases {
		if got := hopsAway(ttl); got != want {
			t.Errorf("hopsAway(%d) = %d, want %d", ttl, got, want)
		}
	}
}

func TestAttributeInjectedRST(t *testing.T) {
	// Server 10 hops (TTL 54); RST only 5 hops (TTL 250) → injector is in-path.
	if got := attributeInjectedRST(54, 250); got != verdict.AttrInNetwork {
		t.Errorf("close injector: got %v, want in_network", got)
	}
	// RST within the hop margin of the server → not clearly in-path.
	if got := attributeInjectedRST(54, 56); got != verdict.AttrUnknown {
		t.Errorf("same-distance: got %v, want unknown", got)
	}
}

// Unavailable capture must degrade to an Info note, never fabricate a verdict.
func TestRSTContributeUnavailable(t *testing.T) {
	f := &RSTFinding{Available: false, Note: "needs raw-socket privilege"}
	v := &verdict.Verdict{Type: verdict.OK}
	f.Contribute(v)
	if v.Type != verdict.OK {
		t.Fatalf("Type = %v, want OK (no fabrication)", v.Type)
	}
	if len(v.Evidence) != 1 || v.Evidence[0].Outcome != verdict.Info {
		t.Errorf("expected one Info evidence, got %+v", v.Evidence)
	}
}

// An injected in-path RST with no stronger explanation yields RST_INJECTION and
// sets in_network attribution.
func TestRSTContributeInjected(t *testing.T) {
	f := &RSTFinding{Available: true, Injected: true, ServerTTL: 54, RSTTTL: 250}
	v := &verdict.Verdict{Type: verdict.OK, Attribution: verdict.AttrUnknown}
	f.Contribute(v)
	if v.Type != verdict.RSTInjection {
		t.Fatalf("Type = %v, want RST_INJECTION", v.Type)
	}
	if v.Attribution != verdict.AttrInNetwork {
		t.Errorf("Attribution = %v, want in_network", v.Attribution)
	}
}

// Control unreachable overrides to LOCAL_ISSUE.
func TestControlOverride(t *testing.T) {
	f := &ControlFinding{Reachable: false}
	v := &verdict.Verdict{Type: verdict.SNIFiltering, Confidence: verdict.High}
	f.Contribute(v)
	if v.Type != verdict.LocalIssue {
		t.Fatalf("Type = %v, want LOCAL_ISSUE", v.Type)
	}
	if v.Attribution != verdict.AttrLocal {
		t.Errorf("Attribution = %v, want local", v.Attribution)
	}
}
