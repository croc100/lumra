package verdict

import "testing"

func TestNatureOf(t *testing.T) {
	cases := map[Type]Nature{
		OK:            NatureNone,
		DNSTampering:  NatureControl,
		SNIFiltering:  NatureControl,
		RSTInjection:  NatureControl,
		IPBlocking:    NatureControl,
		BlockPage:     NatureControl,
		TLSMITM:       NatureSurveillance,
		Throttling:    NatureDegradation,
		LocalIssue:    NatureFault,
		GenuineOutage: NatureFault,
		Inconclusive:  NatureUnknown,
	}
	for typ, want := range cases {
		if got := NatureOf(typ); got != want {
			t.Errorf("NatureOf(%s) = %s, want %s", typ, got, want)
		}
	}
}

// Every declared Type must map to a concrete Nature (never the empty string),
// so a newly added Type can't silently fall through unclassified.
func TestNatureOfTotal(t *testing.T) {
	for _, typ := range []Type{
		OK, DNSTampering, SNIFiltering, RSTInjection, IPBlocking, TLSMITM,
		BlockPage, Throttling, LocalIssue, GenuineOutage, Inconclusive,
	} {
		if NatureOf(typ) == "" {
			t.Errorf("Type %s maps to empty Nature", typ)
		}
	}
}
