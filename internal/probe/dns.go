package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/croc100/lumra/internal/verdict"
)

// dnsSource is one resolver Lumra queries. Plaintext resolvers are what a
// censor can tamper with; DoH resolvers serve as tamper-resistant ground truth.
type dnsSource struct {
	name       string
	groundTrue bool // true = trusted (DoH), used as the reference answer
	server     string
	doh        string // if set, query over DoH-JSON instead of plaintext UDP
}

var dnsSources = []dnsSource{
	{name: "system", server: ""},
	{name: "public-google", server: "8.8.8.8:53"},
	{name: "public-cloudflare", server: "1.1.1.1:53"},
	{name: "doh-cloudflare", groundTrue: true, doh: "https://cloudflare-dns.com/dns-query"},
	{name: "doh-google", groundTrue: true, doh: "https://dns.google/resolve"},
}

// DNSFinding holds the per-source answers and the tampering determination.
type DNSFinding struct {
	Domain      string
	Answers     map[string][]string // source name -> sorted IPv4 answers
	Errors      map[string]string   // source name -> error (if any)
	GroundTruth []string            // union of DoH answers
	Tampered    bool
	Suspicious  []string // plaintext-only IPs that look injected
}

// DNS resolves domain across all sources and compares plaintext answers against
// DoH ground truth to detect manipulation.
func DNS(ctx context.Context, domain string) *DNSFinding {
	f := &DNSFinding{
		Domain:  domain,
		Answers: map[string][]string{},
		Errors:  map[string]string{},
	}

	gt := map[string]bool{}
	for _, s := range dnsSources {
		ips, err := s.lookup(ctx, domain)
		if err != nil {
			f.Errors[s.name] = err.Error()
			continue
		}
		sort.Strings(ips)
		f.Answers[s.name] = ips
		if s.groundTrue {
			for _, ip := range ips {
				gt[ip] = true
			}
		}
	}
	for ip := range gt {
		f.GroundTruth = append(f.GroundTruth, ip)
	}
	sort.Strings(f.GroundTruth)

	// A plaintext answer that resolves outside the DoH ground truth AND points to
	// a bogon/private/loopback address is the signature of an injected answer.
	if len(f.GroundTruth) > 0 {
		seen := map[string]bool{}
		for _, s := range dnsSources {
			if s.groundTrue {
				continue
			}
			for _, ip := range f.Answers[s.name] {
				if gt[ip] || seen[ip] {
					continue
				}
				if isSuspicious(ip) {
					seen[ip] = true
					f.Suspicious = append(f.Suspicious, ip)
					f.Tampered = true
				}
			}
		}
	}
	return f
}

// lookup resolves domain via this source, returning IPv4 addresses.
func (s dnsSource) lookup(ctx context.Context, domain string) ([]string, error) {
	if s.doh != "" {
		return dohLookup(ctx, s.doh, domain)
	}
	r := net.DefaultResolver
	if s.server != "" {
		r = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 3 * time.Second}
				return d.DialContext(ctx, "udp", s.server)
			},
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	addrs, err := r.LookupHost(ctx, domain)
	if err != nil {
		return nil, err
	}
	return onlyIPv4(addrs), nil
}

type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func dohLookup(ctx context.Context, endpoint, domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s?name=%s&type=A", endpoint, domain), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh http %d", resp.StatusCode)
	}
	var dr dohResponse
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return nil, err
	}
	var ips []string
	for _, a := range dr.Answer {
		if a.Type == 1 { // A record
			ips = append(ips, a.Data)
		}
	}
	return ips, nil
}

// Contribute records DNS evidence into v and, if tampering is found, sets the
// verdict type. It does not overwrite a stronger verdict already set.
func (f *DNSFinding) Contribute(v *verdict.Verdict) {
	if f.Tampered {
		v.Add("DNS", verdict.Fail, fmt.Sprintf(
			"plaintext resolvers returned %v, absent from DoH ground truth %v (injected)",
			f.Suspicious, f.GroundTruth))
		if v.Type == verdict.OK || v.Type == verdict.Inconclusive || v.Type == "" {
			v.Type = verdict.DNSTampering
			v.Confidence = verdict.High
			v.Cause = "Plaintext DNS answers diverge from DoH ground truth and " +
				"resolve to bogon/private addresses — the response was injected."
		}
		return
	}
	if len(f.GroundTruth) == 0 {
		v.Add("DNS", verdict.Info, "no DoH ground truth available (DoH may be blocked)")
		return
	}
	v.Add("DNS", verdict.Pass, "consistent with DoH ground truth (no tampering)")
}

func onlyIPv4(addrs []string) []string {
	var out []string
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			out = append(out, a)
		}
	}
	return out
}

// isSuspicious reports whether an IP is the kind a censor injects to sink a
// blocked domain: loopback, private, link-local, unspecified, or bogon.
func isSuspicious(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.Equal(net.IPv4zero)
}
