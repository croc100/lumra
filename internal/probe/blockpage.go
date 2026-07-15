package probe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/croc100/lumra/internal/verdict"
)

// blockServer is an operator-run block/notice endpoint. When a blocked request
// is redirected here, the censoring infrastructure has named itself — the
// strongest, list-free form of attribution.
type blockServer struct {
	hostMatch string // substring that appears in the redirect/body
	authority string // the operator it identifies
	country   string
}

// blockServers is a registry of self-identifying block endpoints. Membership is
// not "this domain is blocked" (that would be a trusted list); it is "this host
// is a known operator's own block server," used only to name an operator once we
// have independently observed a redirect to it.
var blockServers = []blockServer{
	{hostMatch: "warning.or.kr", authority: "KCSC", country: "KR"}, // Korea Communications Standards Commission
}

// BlockPageFinding records whether an HTTP request was diverted to a known
// operator block server.
type BlockPageFinding struct {
	Status    int
	Location  string
	Authority string
	Matched   string // the block-server host we matched
	Country   string
}

// BlockPage issues a plaintext HTTP request to the target and checks whether the
// response redirects to (or its body names) a known operator block server. HTTP
// is where such block pages are injected; HTTPS blocks usually surface as SNI
// resets instead (see the TLS probe).
func BlockPage(ctx context.Context, domain string) *BlockPageFinding {
	f := &BlockPageFinding{}

	client := &http.Client{
		Timeout: 6 * time.Second,
		// Do not follow redirects: the injected 3xx to the block server is exactly
		// the evidence we want to capture.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+domain+"/", nil)
	if err != nil {
		return f
	}
	resp, err := client.Do(req)
	if err != nil {
		return f
	}
	defer resp.Body.Close()

	f.Status = resp.StatusCode
	f.Location = resp.Header.Get("Location")
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10)) // 8 KiB is enough for a block page

	if auth, match, country := classifyBlockPage(f.Location, string(body)); auth != "" {
		f.Authority, f.Matched, f.Country = auth, match, country
	}
	return f
}

// classifyBlockPage matches a redirect target or body snippet against the
// block-server registry, returning the identified authority.
func classifyBlockPage(location, body string) (authority, matched, country string) {
	loc, b := strings.ToLower(location), strings.ToLower(body)
	for _, s := range blockServers {
		if strings.Contains(loc, s.hostMatch) || strings.Contains(b, s.hostMatch) {
			return s.authority, s.hostMatch, s.country
		}
	}
	return "", "", ""
}

// Contribute folds a self-identifying block page into the verdict. A match is
// the strongest attribution signal, so it always sets self-identified
// attribution and names the authority, and supplies a BLOCK_PAGE verdict when no
// stronger type was already found.
func (f *BlockPageFinding) Contribute(v *verdict.Verdict) {
	if f.Authority == "" {
		return
	}
	v.Add("PAGE", verdict.Fail, fmt.Sprintf(
		"blocked request diverted to %s (%s block server)", f.Matched, f.Authority))
	v.Attribution = verdict.AttrSelfIdentified
	v.Authority = f.Authority
	if v.Type == verdict.OK || v.Type == verdict.Inconclusive {
		v.Type = verdict.BlockPage
		v.Confidence = verdict.High
		v.Cause = fmt.Sprintf(
			"The request was diverted to %s, the %s's own block server — the "+
				"censoring infrastructure identifies itself.", f.Matched, f.Authority)
	}
}
