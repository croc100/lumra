package probe

import (
	"testing"

	"github.com/croc100/lumra/internal/verdict"
)

func TestClassifyBlockPage(t *testing.T) {
	// Redirect Location naming the KCSC block server.
	if auth, _, country := classifyBlockPage("http://www.warning.or.kr/", ""); auth != "KCSC" || country != "KR" {
		t.Errorf("redirect: got %q/%q, want KCSC/KR", auth, country)
	}
	// Body-embedded reference.
	if auth, _, _ := classifyBlockPage("", "<html>redirected to warning.or.kr</html>"); auth != "KCSC" {
		t.Errorf("body: got %q, want KCSC", auth)
	}
	// Ordinary redirect → no match.
	if auth, _, _ := classifyBlockPage("https://example.com/login", "hello"); auth != "" {
		t.Errorf("clean: got %q, want empty", auth)
	}
}

// A self-identifying block page sets self-identified attribution, names the
// authority, and supplies a BLOCK_PAGE verdict when nothing stronger was found.
func TestBlockPageContribute(t *testing.T) {
	f := &BlockPageFinding{Authority: "KCSC", Matched: "warning.or.kr", Country: "KR", Status: 302}
	v := &verdict.Verdict{Type: verdict.OK}
	f.Contribute(v)

	if v.Type != verdict.BlockPage {
		t.Fatalf("Type = %v, want BLOCK_PAGE", v.Type)
	}
	if v.Attribution != verdict.AttrSelfIdentified || v.Authority != "KCSC" {
		t.Errorf("attribution = %v/%q, want self_identified/KCSC", v.Attribution, v.Authority)
	}
}

// When SNI filtering was already detected (HTTPS), a block page still enriches
// attribution without downgrading the verdict type.
func TestBlockPageEnrichesExisting(t *testing.T) {
	f := &BlockPageFinding{Authority: "KCSC", Matched: "warning.or.kr", Country: "KR"}
	v := &verdict.Verdict{Type: verdict.SNIFiltering, Confidence: verdict.High}
	f.Contribute(v)

	if v.Type != verdict.SNIFiltering {
		t.Fatalf("Type = %v, want SNI_FILTERING preserved", v.Type)
	}
	if v.Attribution != verdict.AttrSelfIdentified || v.Authority != "KCSC" {
		t.Errorf("expected self_identified/KCSC attribution, got %v/%q", v.Attribution, v.Authority)
	}
}
