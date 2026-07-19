package live

import (
	"testing"
	"time"

	"github.com/croc100/lumra/internal/verdict"
)

func TestRecommend(t *testing.T) {
	cases := map[verdict.Type]Action{
		verdict.OK:           ActionNone,
		verdict.DNSTampering: ActionUseDoH,
		verdict.SNIFiltering: ActionRequire13,
		verdict.TLSDowngrade: ActionRequire13,
		verdict.TLSMITM:      ActionCaution,
		verdict.RSTInjection: ActionBlocked,
		verdict.IPBlocking:   ActionBlocked,
		verdict.BlockPage:    ActionBlocked,
		verdict.Throttling:   ActionNone,
		verdict.Inconclusive: ActionNone,
	}
	for typ, want := range cases {
		if got := Recommend(typ); got != want {
			t.Errorf("Recommend(%s) = %q, want %q", typ, got, want)
		}
	}
}

// Every actionable Action must render a non-empty board label; ActionNone must not.
func TestActionLabel(t *testing.T) {
	if ActionNone.Label() != "" {
		t.Error("ActionNone should have no label")
	}
	for _, a := range []Action{ActionUseDoH, ActionRequire13, ActionCaution, ActionBlocked} {
		if a.Label() == "" {
			t.Errorf("Action %q should have a label", a)
		}
	}
}

func TestSetVerdictAttachesCauseAndAction(t *testing.T) {
	tr := NewTracker()
	now := time.Unix(1000, 0)
	tr.Observe(Event{Kind: ClientHello, Domain: "poisoned.example", At: now})
	tr.SetVerdict("poisoned.example", &verdict.Verdict{
		Type:       verdict.DNSTampering,
		Confidence: verdict.High,
		Cause:      "The resolver returned a forged address.",
	}, now)
	f := tr.Snapshot()[0]
	if f.Action != ActionUseDoH {
		t.Errorf("action = %q, want use-DoH", f.Action)
	}
	if f.DeepCause == "" || f.Nature() != verdict.NatureControl {
		t.Errorf("cause/nature not attached: cause=%q nature=%s", f.DeepCause, f.Nature())
	}
}
