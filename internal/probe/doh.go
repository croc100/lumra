package probe

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/croc100/lumra/internal/verdict"
)

// Adversarial resilience for the diagnosis channel itself. Lumra leans on DoH as
// tamper-resistant ground truth — so a censor who wants to hide DNS tampering has
// an incentive to block DoH too. This file (a) resolves ground truth across a
// pool of independent DoH operators with fallback, so knocking out one provider
// does not blind Lumra, and (b) probes whether DoH as a whole is being blocked,
// which is itself a censorship signal worth surfacing.

// dohProvider is one independent encrypted-DNS operator. Diversity of operator
// matters: a single blocked endpoint must not blind Lumra. Providers speak
// either the DoH-JSON extension (Cloudflare/Google) or the RFC 8484 wireformat
// (the interoperable standard, which every DoH resolver supports).
type dohProvider struct {
	name     string
	endpoint string
	wire     bool // RFC 8484 application/dns-message instead of DoH-JSON
}

// dohProviders is the fallback pool, tried in order. Independent operators so a
// targeted block of one (or its anycast IPs) leaves the others as ground truth.
var dohProviders = []dohProvider{
	{name: "cloudflare", endpoint: "https://cloudflare-dns.com/dns-query"},
	{name: "google", endpoint: "https://dns.google/resolve"},
	{name: "quad9", endpoint: "https://dns.quad9.net/dns-query", wire: true},
}

// resolve looks up domain via this provider, over JSON or wireformat.
func (p dohProvider) resolve(ctx context.Context, domain string) ([]string, error) {
	if p.wire {
		return dohWireLookup(ctx, p.endpoint, domain)
	}
	return dohLookup(ctx, p.endpoint, domain)
}

// dohWireLookup resolves domain over RFC 8484 DoH: an A query packed to the
// standard DNS wireformat, sent base64url in the ?dns= parameter, and parsed
// back with the same wire parser the duplicate-response probe uses. ID 0 per
// RFC 8484 §4.1 (the transport is already unique per HTTP request).
func dohWireLookup(ctx context.Context, endpoint, domain string) ([]string, error) {
	query, err := buildAQuery(0, domain)
	if err != nil {
		return nil, err
	}
	url := endpoint + "?dns=" + base64.RawURLEncoding.EncodeToString(query)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	ips, ok := parseAAnswers(body, 0)
	if !ok {
		return nil, fmt.Errorf("doh: malformed wireformat response")
	}
	return ips, nil
}

// resolveDoHPool returns the first successful DoH resolution of domain, trying
// each provider in turn. The provider name is returned so the caller can record
// which channel survived. It fails only if every provider fails.
func resolveDoHPool(ctx context.Context, domain string) (ips []string, provider string, err error) {
	var errs []string
	for _, p := range dohProviders {
		got, e := p.resolve(ctx, domain)
		if e == nil && len(got) > 0 {
			return got, p.name, nil
		}
		if e != nil {
			errs = append(errs, p.name+": "+e.Error())
		} else {
			errs = append(errs, p.name+": empty answer")
		}
	}
	return nil, "", fmt.Errorf("all DoH providers failed: %s", strings.Join(errs, "; "))
}

// groundTruthDoH resolves domain across every provider and unions the answers,
// returning the union and the names of the providers that responded. Unioning
// across operators reduces false positives from CDN/geo spread; the reachable
// list drives the DoH-health assessment. A domain with no A record anywhere
// yields an empty union but still reports which providers were reachable.
func groundTruthDoH(ctx context.Context, domain string) (union []string, reachable []string) {
	set := map[string]bool{}
	for _, p := range dohProviders {
		got, err := p.resolve(ctx, domain)
		if err != nil {
			continue
		}
		reachable = append(reachable, p.name)
		for _, ip := range got {
			set[ip] = true
		}
	}
	for ip := range set {
		union = append(union, ip)
	}
	sort.Strings(union)
	return union, reachable
}

// dohStatus is the health of the encrypted-DNS channel as a whole.
type dohStatus string

const (
	dohHealthy  dohStatus = "healthy"  // every provider reachable
	dohDegraded dohStatus = "degraded" // some providers blocked, fallback holds
	dohBlocked  dohStatus = "blocked"  // no provider reachable while plaintext works
	dohOffline  dohStatus = "offline"  // no provider reachable and no plaintext either (not DoH-specific)
)

// DoHFinding reports whether Lumra's tamper-resistant channel is under attack.
type DoHFinding struct {
	Reachable   []string // providers that answered
	Total       int      // providers attempted
	PlaintextOK bool     // a plaintext resolver reached the canary (isolates DoH-specific blocking)
	Status      dohStatus
	Confidence  verdict.Confidence
}

// dohCanary is a stable, universally-resolvable name used only to test whether
// the DoH channel works — never a sensitive target.
const dohCanary = "example.com"

// DoHHealth probes every DoH provider with a canary lookup and, using a plaintext
// control lookup to rule out a plain outage, classifies whether encrypted DNS is
// being blocked. Blocking DoH is an adversary attacking the diagnosis itself.
func DoHHealth(ctx context.Context) *DoHFinding {
	f := &DoHFinding{Total: len(dohProviders)}
	_, f.Reachable = groundTruthDoH(ctx, dohCanary)

	// Plaintext control: if a public plaintext resolver reaches the canary but no
	// DoH provider does, the block is DoH-specific rather than a plain outage.
	src := dnsSource{name: "canary-plain", server: "8.8.8.8:53"}
	if ips, err := src.lookup(ctx, dohCanary); err == nil && len(ips) > 0 {
		f.PlaintextOK = true
	}

	f.Status, f.Confidence = assessDoH(len(f.Reachable), f.Total, f.PlaintextOK)
	return f
}

// assessDoH is the pure classification of DoH channel health. Kept separate so
// the decision boundary is unit-tested without the network.
func assessDoH(reachable, total int, plaintextOK bool) (dohStatus, verdict.Confidence) {
	switch {
	case reachable == 0 && plaintextOK:
		// Every encrypted-DNS operator is unreachable, yet plaintext DNS works —
		// the encrypted channel is being singled out.
		return dohBlocked, verdict.High
	case reachable == 0:
		// Nothing resolves at all; this is a general outage, not DoH-specific.
		return dohOffline, verdict.Low
	case reachable < total:
		return dohDegraded, verdict.Medium
	default:
		return dohHealthy, verdict.High
	}
}

// Contribute records the DoH-channel finding into v. It asserts DOH_BLOCKING only
// when the encrypted channel is provably singled out and no stronger target
// verdict was already reached; degraded/healthy states are informational.
func (f *DoHFinding) Contribute(v *verdict.Verdict) {
	switch f.Status {
	case dohBlocked:
		v.Add("DoH", verdict.Fail, fmt.Sprintf(
			"every DoH provider (%d) is unreachable while plaintext DNS resolves %s — the encrypted-DNS channel is being blocked",
			f.Total, dohCanary))
		if canSet(v.Type) {
			v.Type = verdict.DoHBlocking
			v.Confidence = f.Confidence
			v.Cause = "Encrypted DNS (DoH) is being blocked wholesale: no provider is " +
				"reachable even though plaintext DNS works. Blocking the tamper-resistant " +
				"channel is itself an act of interference — and it is where DNS tampering hides."
		}
	case dohDegraded:
		v.Add("DoH", verdict.Info, fmt.Sprintf(
			"DoH partially blocked: only %v of %d providers reachable — fallback is holding ground truth",
			f.Reachable, f.Total))
	case dohOffline:
		v.Add("DoH", verdict.Info, "no DoH provider reachable, and plaintext DNS is also down — general connectivity fault, not DoH-specific")
	default:
		v.Add("DoH", verdict.Pass, fmt.Sprintf("all %d DoH providers reachable — tamper-resistant channel healthy", f.Total))
	}
}
