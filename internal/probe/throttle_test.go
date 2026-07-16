package probe

import (
	"testing"

	"github.com/croc100/lumra/internal/verdict"
)

func TestAssessThrottle(t *testing.T) {
	const floor = throttleFloorBps
	tests := []struct {
		name          string
		target        float64
		control       float64
		wantMeasured  bool
		wantThrottled bool
	}{
		{"both silent", 0, 0, false, false},
		{"target silent", 0, 4 << 20, false, false},
		{"no control baseline", 100 << 10, 0, false, false},
		{"target healthy", floor + 1, 8 << 20, true, false},
		{"both slow congestion", 60 << 10, 120 << 10, true, false},
		{"selective throttle", 80 << 10, 8 << 20, true, true},
		{"slow but control not decisive", 100 << 10, 300 << 10, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			measured, throttled, note := assessThrottle(tt.target, tt.control)
			if measured != tt.wantMeasured || throttled != tt.wantThrottled {
				t.Errorf("assessThrottle(%.0f, %.0f) = measured %v, throttled %v; want %v, %v (%s)",
					tt.target, tt.control, measured, throttled, tt.wantMeasured, tt.wantThrottled, note)
			}
			if note == "" {
				t.Error("expected a non-empty note")
			}
		})
	}
}

// A confirmed throttle sets the verdict only when nothing stronger fired.
func TestThrottleContributePrecedence(t *testing.T) {
	throttled := &ThrottleFinding{Measured: true, Throttled: true, Note: "n"}

	// Fresh verdict: throttling should be adopted.
	v := &verdict.Verdict{Type: verdict.OK, Confidence: verdict.Low}
	throttled.Contribute(v)
	if v.Type != verdict.Throttling {
		t.Fatalf("on a clean verdict, want THROTTLING, got %s", v.Type)
	}
	if v.Confidence != verdict.Medium {
		t.Errorf("want medium confidence, got %s", v.Confidence)
	}

	// A hard block already concluded: throttling must not override it.
	blocked := &verdict.Verdict{Type: verdict.SNIFiltering, Confidence: verdict.High}
	throttled.Contribute(blocked)
	if blocked.Type != verdict.SNIFiltering {
		t.Fatalf("throttling overrode a hard block: got %s", blocked.Type)
	}
}

// A healthy or unmeasured result never sets the verdict type.
func TestThrottleContributeNoFalsePositive(t *testing.T) {
	for _, f := range []*ThrottleFinding{
		{Measured: true, Throttled: false, Note: "healthy"},
		{Measured: false, Note: "insufficient"},
	} {
		v := &verdict.Verdict{Type: verdict.OK, Confidence: verdict.Low}
		f.Contribute(v)
		if v.Type != verdict.OK {
			t.Errorf("non-throttled finding changed verdict to %s", v.Type)
		}
		if len(v.Evidence) != 1 {
			t.Errorf("want one evidence record, got %d", len(v.Evidence))
		}
	}
}
