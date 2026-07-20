package probe

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/croc100/lumra/internal/verdict"
)

// Encrypted ClientHello (ECH) closes the last cleartext leak in a TLS 1.3
// handshake: the SNI. A censor that filters on SNI therefore has an incentive to
// block ECH specifically — tearing down handshakes that carry an encrypted
// ClientHello while letting plain ones through, so the destination stays
// filterable. That selective reset is the signal this probe looks for.
//
// The probe needs the target's ECHConfigList, which is published in the DNS
// HTTPS resource record (type 65) under SvcParamKey 5 ("ech"). Lumra fetches it
// over the resilient DoH pool (tamper-resistant), then compares a plain TLS 1.3
// handshake against an ECH handshake to the same ground-truth IP. A reset that
// hits only the ECH arm is ECH being singled out on the path.

// ECHFinding records the two handshake arms and whether ECH is published.
type ECHFinding struct {
	Domain    string
	IP        string
	HasConfig bool           // the target advertises an ECHConfigList in DNS
	Plain     versionAttempt // TLS 1.3 without ECH
	ECH       versionAttempt // TLS 1.3 with EncryptedClientHelloConfigList set
}

// ECH probes ip:443 for ECH-specific blocking. ip should be a ground-truth
// address so a poisoned DNS answer cannot skew the comparison.
func ECH(ctx context.Context, domain, ip string) *ECHFinding {
	f := &ECHFinding{Domain: domain, IP: ip}
	cfg, ok := fetchECHConfigList(ctx, domain)
	if !ok {
		return f // target does not advertise ECH; nothing to test
	}
	f.HasConfig = true
	f.Plain = versionHandshake(ctx, ip, domain, tls.VersionTLS13)
	f.ECH = echHandshake(ctx, ip, domain, cfg)
	return f
}

// echHandshake dials ip:443 and performs a TLS 1.3 handshake offering ECH with
// the given config list. An ECH rejection (server-side, retry configs returned)
// is a completed handshake, not a path attack — it is recorded as HandshakeOK so
// the classifier does not confuse it with a reset.
func echHandshake(ctx context.Context, ip, sni string, echConfig []byte) versionAttempt {
	var a versionAttempt
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		classifyVersionErr(&a, err)
		return a
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	cfg := &tls.Config{
		ServerName:                     sni,
		InsecureSkipVerify:             true,
		MinVersion:                     tls.VersionTLS13,
		EncryptedClientHelloConfigList: echConfig,
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		// An ECH rejection means the handshake reached the server and it declined
		// ECH — the encrypted-ClientHello path itself was NOT blocked on the wire.
		var rej *tls.ECHRejectionError
		if errors.As(err, &rej) {
			a.HandshakeOK = true
			return a
		}
		classifyVersionErr(&a, err)
		return a
	}
	a.HandshakeOK = true
	a.Negotiated = tc.ConnectionState().Version
	return a
}

// classifyECH decides whether ECH is being blocked on the path. Pure — unit
// tested. The signal requires a working plain TLS 1.3 handshake AND an ECH arm
// that is torn down with a reset: if the plain arm also fails, the fault is not
// ECH-specific; if the ECH arm merely times out or is rejected, that is not a
// deliberate reset.
func classifyECH(plain, ech versionAttempt) (verdict.Confidence, bool) {
	if !plain.HandshakeOK {
		return "", false // no baseline to compare against
	}
	if ech.Reset {
		return verdict.Medium, true
	}
	return "", false
}

// Contribute folds the ECH finding into the verdict.
func (f *ECHFinding) Contribute(v *verdict.Verdict) {
	if !f.HasConfig {
		v.Add("ECH", verdict.Info, fmt.Sprintf("%s does not advertise ECH in DNS — nothing to test", f.Domain))
		return
	}
	conf, blocked := classifyECH(f.Plain, f.ECH)
	if !blocked {
		if f.ECH.HandshakeOK {
			v.Add("ECH", verdict.Pass, fmt.Sprintf("Encrypted ClientHello handshake to %s completed — ECH is not being blocked", f.IP))
		} else {
			v.Add("ECH", verdict.Info, fmt.Sprintf("ECH advertised but the encrypted handshake to %s was inconclusive (%s)", f.IP, f.ECH.Err))
		}
		return
	}
	v.Add("ECH", verdict.Fail, fmt.Sprintf(
		"a plain TLS 1.3 handshake to %s works, but the same handshake carrying an Encrypted ClientHello is reset — ECH is being blocked on the path",
		f.IP))
	if canSet(v.Type) {
		v.Type = verdict.ECHBlocking
		v.Confidence = conf
		v.Cause = "Encrypted ClientHello (ECH) hides the destination name from the network. " +
			"A plain handshake succeeds while the ECH handshake is torn down with a reset — the " +
			"path is singling out ECH to keep the SNI visible and filterable. Blocking the one " +
			"feature that closes the SNI leak is itself an act of interference."
	}
}

// --- ECHConfigList retrieval from the DNS HTTPS record -----------------------

// fetchECHConfigList resolves the domain's HTTPS resource record over the DoH
// pool and returns the ECHConfigList from its "ech" SvcParam, if present.
func fetchECHConfigList(ctx context.Context, domain string) ([]byte, bool) {
	for _, p := range dohProviders {
		rdata, ok := dohHTTPSRecord(ctx, p, domain)
		if !ok {
			continue
		}
		if ech, ok := echFromSvcParams(rdata); ok {
			return ech, true
		}
	}
	return nil, false
}

// dohHTTPSRecord queries one provider for the HTTPS (type 65) record and returns
// the raw RDATA of the first answer. Uses wireformat so the binary SvcParams are
// available directly (the JSON API returns presentation text).
func dohHTTPSRecord(ctx context.Context, p dohProvider, domain string) ([]byte, bool) {
	query, err := buildQuery(0, domain, dnsmessage.TypeHTTPS)
	if err != nil {
		return nil, false
	}
	// The JSON endpoints (google/cloudflare) also answer wireformat at the same
	// path, so query every provider over wireformat here.
	endpoint := p.endpoint
	url := endpoint + "?dns=" + base64.RawURLEncoding.EncodeToString(query)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("Accept", "application/dns-message")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return nil, false
	}
	defer resp.Body.Close()
	body := make([]byte, 0, 1024)
	buf := make([]byte, 4096)
	for {
		n, e := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if e != nil || len(body) > 65535 {
			break
		}
	}
	return firstHTTPSRDATA(body)
}

// firstHTTPSRDATA parses a DNS response and returns the RDATA of the first HTTPS
// (type 65) answer record. Bounds handled by the dnsmessage parser.
func firstHTTPSRDATA(msg []byte) ([]byte, bool) {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return nil, false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, false
	}
	for {
		h, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return nil, false
		}
		if err != nil {
			return nil, false
		}
		if h.Type == dnsmessage.TypeHTTPS {
			r, err := p.UnknownResource()
			if err != nil {
				return nil, false
			}
			return r.Data, true
		}
		if err := p.SkipAnswer(); err != nil {
			return nil, false
		}
	}
}

// echFromSvcParams parses an HTTPS/SVCB RDATA and returns the value of the "ech"
// SvcParam (key 5). RDATA layout: SvcPriority(2) + TargetName + SvcParams, each
// param being key(2) + length(2) + value. Fully bounds-checked over wire data.
func echFromSvcParams(rdata []byte) ([]byte, bool) {
	if len(rdata) < 2 {
		return nil, false
	}
	p := rdata[2:] // skip SvcPriority
	// TargetName: a sequence of length-prefixed labels ending in a zero-length
	// label. AliasMode/root target is a single zero byte.
	for len(p) > 0 {
		l := int(p[0])
		p = p[1:]
		if l == 0 {
			break
		}
		if len(p) < l {
			return nil, false
		}
		p = p[l:]
	}
	// SvcParams, ordered by ascending key.
	for len(p) >= 4 {
		key := binary.BigEndian.Uint16(p)
		vlen := int(binary.BigEndian.Uint16(p[2:]))
		p = p[4:]
		if len(p) < vlen {
			return nil, false
		}
		if key == 5 { // ech
			return p[:vlen], true
		}
		p = p[vlen:]
	}
	return nil, false
}
