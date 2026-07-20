package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

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

// dnsSources are the plaintext resolvers Lumra compares against ground truth.
// DoH ground truth is gathered separately via the resilient provider pool (see
// groundTruthDoH in doh.go) so a single blocked DoH endpoint cannot blind us.
var dnsSources = []dnsSource{
	{name: "system", server: ""},
	{name: "public-google", server: "8.8.8.8:53"},
	{name: "public-cloudflare", server: "1.1.1.1:53"},
}

// dnsReason names which injection signature fired, for the evidence line.
type dnsReason string

const (
	reasonNone      dnsReason = ""
	reasonBogon     dnsReason = "bogon"     // plaintext answer diverges to a bogon/private IP
	reasonNXDOMAIN  dnsReason = "nxdomain"  // plaintext denies a name DoH resolves fine
	reasonDuplicate dnsReason = "duplicate" // two distinct responses raced one query
)

// DNSFinding holds the per-source answers and the tampering determination.
type DNSFinding struct {
	Domain      string
	Answers     map[string][]string // source name -> sorted IPv4 answers
	Errors      map[string]string   // source name -> error (if any)
	NotFound    map[string]bool     // source name -> got NXDOMAIN
	GroundTruth []string            // union of DoH answers

	// Derived by assess():
	Tampered        bool
	Reason          dnsReason
	Confidence      verdict.Confidence
	Suspicious      []string // bogon/private IPs absent from ground truth
	DivergentPublic []string // public IPs absent from ground truth (info only — CDN/geo is normal)
	NXSource        string   // resolver that returned NXDOMAIN
	Duplicated      bool     // duplicate-response injection observed
	DupNote         string
}

// DNS resolves domain across all sources, compares plaintext answers against DoH
// ground truth, and probes one plaintext resolver for duplicate-response
// injection. The classification itself is pure (assess), so it is unit-tested.
func DNS(ctx context.Context, domain string) *DNSFinding {
	f := &DNSFinding{
		Domain:   domain,
		Answers:  map[string][]string{},
		Errors:   map[string]string{},
		NotFound: map[string]bool{},
	}

	for _, s := range dnsSources {
		ips, err := s.lookup(ctx, domain)
		if err != nil {
			f.Errors[s.name] = err.Error()
			var de *net.DNSError
			if errors.As(err, &de) && de.IsNotFound {
				f.NotFound[s.name] = true
			}
			continue
		}
		sort.Strings(ips)
		f.Answers[s.name] = ips
	}

	// Ground truth from the resilient DoH pool: a union across independent
	// operators, tolerant of any one being blocked.
	f.GroundTruth, _ = groundTruthDoH(ctx, domain)

	// Duplicate-response probe against a plaintext public resolver: an injected
	// answer races the real one, so one query draws two distinct responses.
	if dup, note := dnsDuplicateResponse(ctx, "8.8.8.8:53", domain); dup {
		f.Duplicated, f.DupNote = true, note
	}

	f.assess()
	return f
}

// assess is the pure classification step over the gathered data. Order of
// strength: a duplicate-response injection is the hardest wire evidence, then a
// bogon divergence or an NXDOMAIN denial contradicting DoH. A divergence to a
// *public* IP is recorded but never asserted as tampering — CDNs and geo-DNS do
// that legitimately all the time.
func (f *DNSFinding) assess() {
	if len(f.GroundTruth) > 0 {
		gtset := map[string]bool{}
		for _, ip := range f.GroundTruth {
			gtset[ip] = true
		}
		seenB, seenP := map[string]bool{}, map[string]bool{}
		for _, s := range dnsSources {
			if s.groundTrue {
				continue
			}
			// NXDOMAIN injection: denied on plaintext, resolvable over DoH.
			if f.NotFound[s.name] && f.Reason == reasonNone {
				f.Tampered, f.Reason, f.Confidence, f.NXSource = true, reasonNXDOMAIN, verdict.High, s.name
			}
			for _, ip := range f.Answers[s.name] {
				if gtset[ip] {
					continue
				}
				if isSuspicious(ip) {
					if !seenB[ip] {
						seenB[ip] = true
						f.Suspicious = append(f.Suspicious, ip)
					}
				} else if !seenP[ip] {
					seenP[ip] = true
					f.DivergentPublic = append(f.DivergentPublic, ip)
				}
			}
		}
		if len(f.Suspicious) > 0 {
			f.Tampered, f.Confidence = true, verdict.High
			if f.Reason == reasonNone {
				f.Reason = reasonBogon
			}
		}
	}

	// A duplicate-response injection overrides the reason: it is direct wire
	// proof, independent of whether the forged IP is a bogon.
	if f.Duplicated {
		f.Tampered, f.Reason, f.Confidence = true, reasonDuplicate, verdict.High
	}

	sort.Strings(f.Suspicious)
	sort.Strings(f.DivergentPublic)
}

// ResolveDoH returns tamper-resistant ground-truth IPv4 addresses for domain,
// trying the DoH provider pool in order so a single blocked operator does not
// stop the resolution. It is the resolver the live cockpit's enforcer uses to
// write a correct override when DNS tampering is detected.
func ResolveDoH(ctx context.Context, domain string) ([]string, error) {
	ips, _, err := resolveDoHPool(ctx, domain)
	return ips, err
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
		v.Add("DNS", verdict.Fail, f.evidence())
		if canSet(v.Type) {
			v.Type = verdict.DNSTampering
			v.Confidence = f.Confidence
			v.Cause = f.cause()
		}
		return
	}
	if len(f.DivergentPublic) > 0 {
		v.Add("DNS", verdict.Info, fmt.Sprintf(
			"plaintext answers %v differ from DoH ground truth %v but are public — CDN/geo-DNS is normal, not asserting tampering",
			f.DivergentPublic, f.GroundTruth))
		return
	}
	if len(f.GroundTruth) == 0 {
		v.Add("DNS", verdict.Info, "no DoH ground truth available (DoH may be blocked)")
		return
	}
	v.Add("DNS", verdict.Pass, "consistent with DoH ground truth (no tampering)")
}

// evidence renders the one-line evidence detail for the fired signature.
func (f *DNSFinding) evidence() string {
	switch f.Reason {
	case reasonDuplicate:
		return f.DupNote
	case reasonNXDOMAIN:
		return fmt.Sprintf("%s returned NXDOMAIN while DoH resolves %s to %v — the name is being denied on the plaintext path",
			f.NXSource, f.Domain, f.GroundTruth)
	default: // bogon
		return fmt.Sprintf("plaintext resolvers returned %v, absent from DoH ground truth %v and pointing to bogon/private space (injected)",
			f.Suspicious, f.GroundTruth)
	}
}

func (f *DNSFinding) cause() string {
	switch f.Reason {
	case reasonDuplicate:
		return "A single DNS query drew more than one distinct response — a forged answer " +
			"was injected on the path, racing the resolver's real reply."
	case reasonNXDOMAIN:
		return "A plaintext resolver denies the domain exists while DoH resolves it normally — " +
			"the name is being suppressed on the local DNS path."
	default:
		return "Plaintext DNS answers diverge from DoH ground truth and resolve to " +
			"bogon/private addresses — the response was injected."
	}
}

// --- Duplicate-response injection probe -------------------------------------

// dnsDuplicateResponse sends one A query over UDP and collects every response
// that arrives within a short window. Two responses with different answer sets
// to a single query is the signature of an on-path injector: its forged reply
// races the resolver's genuine one. Returns false on any error or a single
// answer — it never guesses.
func dnsDuplicateResponse(ctx context.Context, server, domain string) (bool, string) {
	id := uint16(time.Now().UnixNano())
	query, err := buildAQuery(id, domain)
	if err != nil {
		return false, ""
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	if _, err := conn.Write(query); err != nil {
		return false, ""
	}

	deadline := time.Now().Add(2 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	var msgs [][]byte
	buf := make([]byte, 1500)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(deadline)
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		msgs = append(msgs, append([]byte(nil), buf[:n]...))
		// An injected reply races the real one by milliseconds; once the first
		// response is in, only wait a short grace window for a second, rather
		// than blocking on the full deadline.
		if grace := time.Now().Add(400 * time.Millisecond); grace.Before(deadline) {
			deadline = grace
		}
	}

	sets := distinctAnswerSets(msgs, id)
	if len(sets) >= 2 {
		return true, fmt.Sprintf(
			"resolver %s returned %d distinct responses to one query (%s) — a forged answer raced the real one",
			server, len(sets), strings.Join(sets, " vs "))
	}
	return false, ""
}

// distinctAnswerSets parses each datagram and returns the distinct A-record
// answer sets whose header ID matches. Pure — the core of duplicate detection,
// unit-tested with crafted packets.
func distinctAnswerSets(msgs [][]byte, wantID uint16) []string {
	var sets []string
	for _, m := range msgs {
		ips, ok := parseAAnswers(m, wantID)
		if !ok || len(ips) == 0 {
			continue
		}
		sort.Strings(ips)
		key := strings.Join(ips, ",")
		if !containsStr(sets, key) {
			sets = append(sets, key)
		}
	}
	return sets
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// buildAQuery marshals a standard recursive A-record query for domain.
func buildAQuery(id uint16, domain string) ([]byte, error) {
	return buildQuery(id, domain, dnsmessage.TypeA)
}

// buildQuery marshals a recursive query for domain of the given record type.
func buildQuery(id uint16, domain string, qtype dnsmessage.Type) ([]byte, error) {
	name, err := dnsmessage.NewName(fqdn(domain))
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name: name, Type: qtype, Class: dnsmessage.ClassINET,
		}},
	}
	return msg.Pack()
}

// parseAAnswers extracts the A-record answers from a DNS response, requiring the
// header ID to match. ok=false for anything malformed or mismatched.
func parseAAnswers(msg []byte, wantID uint16) ([]string, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || h.ID != wantID {
		return nil, false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, false
	}
	var ips []string
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, false
		}
		if ah.Type == dnsmessage.TypeA {
			r, err := p.AResource()
			if err != nil {
				return nil, false
			}
			ips = append(ips, net.IP(r.A[:]).String())
		} else if err := p.SkipAnswer(); err != nil {
			return nil, false
		}
	}
	return ips, true
}

func fqdn(d string) string {
	if strings.HasSuffix(d, ".") {
		return d
	}
	return d + "."
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
