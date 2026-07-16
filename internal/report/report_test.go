package report

import (
	"strings"
	"testing"
	"time"

	"github.com/croc100/lumra/internal/verdict"
)

func TestHTMLRendersVerdict(t *testing.T) {
	v := &verdict.Verdict{
		Target: "news.example.kr", Type: verdict.SNIFiltering, Confidence: verdict.High,
		Attribution: verdict.AttrInNetwork, Authority: "KCSC",
		Cause: "middlebox reset on target SNI",
	}
	v.Add("TLS", verdict.Fail, "SNI reset on same IP")
	v.Add("CTRL", verdict.Pass, "baseline reachable")

	out, err := HTML(v, time.Date(2026, 7, 16, 14, 32, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		"news.example.kr", "SNI_FILTERING", "confidence", ">high<",
		"in_network", "KCSC", "middlebox reset on target SNI",
		"SNI reset on same IP", "baseline reachable",
		"2026-07-16 14:32:00 UTC", "<!DOCTYPE html>",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("report missing %q", want)
		}
	}
	// The blocked verdict must drive the blocked accent class.
	if !strings.Contains(s, `verdict blocked`) {
		t.Error("blocked verdict should carry the .blocked class")
	}
}

func TestHTMLEscapesInjection(t *testing.T) {
	v := &verdict.Verdict{Target: "<script>x</script>", Type: verdict.OK, Confidence: verdict.Low}
	out, err := HTML(v, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "<script>x</script>") {
		t.Error("target was not HTML-escaped — injection risk")
	}
}
