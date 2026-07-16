package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/croc100/lumra/internal/verdict"
)

// benignSNI is an SNI a censor's blocklist will not contain, used as the control
// arm. example.com is IANA-reserved and never appears on a real block list, so a
// reset seen only with the target SNI (and not this one) isolates SNI filtering.
const benignSNI = "www.example.com"

// tlsAttempt records the outcome of one handshake to a fixed IP with a given SNI.
type tlsAttempt struct {
	SNI         string
	Connected   bool // TCP handshake completed
	HandshakeOK bool // TLS handshake completed
	Reset       bool // connection reset (RST) — the middlebox signature
	Timeout     bool // no response (possible blackhole)
	Err         string
	// Certificate verification against the system roots (target arm only).
	CertUntrusted bool   // chain does not reach a trusted CA — substitution/MITM signal
	CertExpired   bool   // chain is trusted but expired — not interference
	CertHostErr   bool   // valid chain, wrong hostname — weak signal
	CertSubject   string // leaf subject CN, for the evidence line
	cert          *x509.Certificate
}

// TLSFinding compares a handshake carrying the target SNI against one carrying a
// benign SNI on the same IP.
type TLSFinding struct {
	Domain string
	IP     string
	Target tlsAttempt
	Benign tlsAttempt
}

// TLS probes ip:443 twice — once with the target SNI, once with a benign SNI —
// to detect SNI-based filtering. ip should be a ground-truth address (DoH) so a
// poisoned DNS answer does not send the probe to a sinkhole.
func TLS(ctx context.Context, domain, ip string) *TLSFinding {
	return &TLSFinding{
		Domain: domain,
		IP:     ip,
		Target: handshake(ctx, ip, domain),
		Benign: handshake(ctx, ip, benignSNI),
	}
}

func handshake(ctx context.Context, ip, sni string) tlsAttempt {
	a := tlsAttempt{SNI: sni}

	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		a.classify(err)
		return a
	}
	defer conn.Close()
	a.Connected = true

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	// InsecureSkipVerify: we are inspecting the handshake and cert, not trusting
	// it. A trust failure is not interference; a reset is what we care about.
	tc := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	if err := tc.HandshakeContext(ctx); err != nil {
		a.classify(err)
		return a
	}
	a.HandshakeOK = true
	if certs := tc.ConnectionState().PeerCertificates; len(certs) > 0 {
		a.cert = certs[0]
		a.verifyPeerChain(certs, sni)
	}
	return a
}

// verifyPeerChain checks the presented chain against the system roots for sni
// and records why it failed, so the verdict can tell a substituted certificate
// (interception) apart from a merely expired or wrong-host one.
func (a *tlsAttempt) verifyPeerChain(certs []*x509.Certificate, sni string) {
	a.CertSubject = certs[0].Subject.CommonName
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{DNSName: sni, Intermediates: inter})
	a.CertUntrusted, a.CertExpired, a.CertHostErr = classifyCert(err)
}

// classifyCert maps a certificate-verification error to the reason that matters
// for interference. Untrusted-authority is the substitution signal; expired and
// hostname errors are ordinary and must not be reported as MITM.
func classifyCert(err error) (untrusted, expired, hostErr bool) {
	if err == nil {
		return false, false, false
	}
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	if errors.As(err, &ua) {
		untrusted = true
	}
	if errors.As(err, &he) {
		hostErr = true
	}
	if errors.As(err, &ci) && ci.Reason == x509.Expired {
		expired = true
	}
	return untrusted, expired, hostErr
}

// classifyReachability decides, from the two handshake arms, whether the target
// IP is being blocked at the IP level (reset regardless of SNI) or is a silent
// blackhole (ambiguous with a genuine outage from a single vantage). It returns
// an empty type when neither pattern is present. Pure — unit-tested.
func classifyReachability(target, benign tlsAttempt) (verdict.Type, verdict.Confidence) {
	// Every connection to the IP is reset, independent of the SNI presented →
	// the address itself is being reset, not a specific hostname.
	if target.Reset && benign.Reset {
		return verdict.IPBlocking, verdict.Medium
	}
	// Nothing answers on either arm and it is not a reset → silent drop. A single
	// vantage cannot split an IP-level block from a real server outage.
	if !target.Connected && !benign.Connected && !target.Reset && !benign.Reset {
		return verdict.Inconclusive, verdict.Low
	}
	return "", ""
}

// classify maps a dial/handshake error to interference-relevant categories.
func (a *tlsAttempt) classify(err error) {
	a.Err = err.Error()
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		a.Timeout = true
		return
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "reset") || errors.Is(err, net.ErrClosed) ||
		strings.Contains(msg, "broken pipe") || strings.Contains(msg, "eof") {
		a.Reset = true
	}
}

// Contribute folds the TLS/SNI finding into the verdict.
func (f *TLSFinding) Contribute(v *verdict.Verdict) {
	// Certificate substitution: the handshake completes but the presented chain
	// does not reach a trusted root for the target — the session is intercepted
	// and re-signed. Expired/wrong-host certs are ordinary and excluded.
	if f.Target.HandshakeOK && f.Target.CertUntrusted {
		v.Add("TLS", verdict.Fail, fmt.Sprintf(
			"handshake completed but the certificate for %s does not chain to a trusted root (subject %q) — cert substitution",
			f.Domain, f.Target.CertSubject))
		if canSet(v.Type) {
			v.Type = verdict.TLSMITM
			v.Confidence = verdict.Medium
			v.Cause = "The TLS handshake completes, but the certificate presented for the " +
				"target does not chain to a trusted certificate authority — the session is " +
				"being intercepted and re-signed (man-in-the-middle)."
		}
		return
	}

	// Strongest block signal: target SNI is reset while a benign SNI is accepted
	// on the same IP. That isolates the reset to the SNI value → SNI filtering.
	if f.Target.Reset && (f.Benign.HandshakeOK || (f.Benign.Connected && !f.Benign.Reset)) {
		v.Add("TLS", verdict.Fail, fmt.Sprintf(
			"SNI=%s → connection reset; SNI=%s → accepted on same IP %s",
			f.Domain, benignSNI, f.IP))
		v.Type = verdict.SNIFiltering
		v.Confidence = verdict.High
		v.Cause = "TLS connections carrying the target SNI are reset by a middlebox, " +
			"while the same IP completes a handshake with a benign SNI — the reset " +
			"is triggered by the SNI value, the signature of SNI-based filtering."
		return
	}

	if f.Target.HandshakeOK {
		v.Add("TLS", verdict.Pass, fmt.Sprintf("handshake OK with target SNI on %s", f.IP))
		return
	}

	// Not SNI-specific and not a clean handshake → classify IP reachability.
	switch t, conf := classifyReachability(f.Target, f.Benign); t {
	case verdict.IPBlocking:
		v.Add("TLS", verdict.Fail, fmt.Sprintf(
			"every TLS connection to %s is reset regardless of SNI — IP-level block, not hostname-keyed", f.IP))
		if canSet(v.Type) {
			v.Type = verdict.IPBlocking
			v.Confidence = conf
			v.Cause = "Connections to the destination IP are reset regardless of the SNI " +
				"presented — the address itself is blocked, not a specific hostname."
		}
		return
	case verdict.Inconclusive:
		v.Add("TLS", verdict.Info, fmt.Sprintf(
			"%s:443 did not answer on any attempt — an IP-level block and a genuine outage are indistinguishable from one vantage", f.IP))
		if v.Type == verdict.OK || v.Type == "" {
			v.Type = verdict.Inconclusive
			v.Confidence = verdict.Low
			v.Cause = "The destination IP did not answer on any connection while the rest of " +
				"the network is reachable; from a single vantage this cannot be split between " +
				"an IP-level block and a genuine server outage."
		}
		return
	}

	if !f.Target.Connected {
		v.Add("TLS", verdict.Info, fmt.Sprintf("TCP to %s:443 failed (%s)", f.IP, f.Target.Err))
		return
	}
	v.Add("TLS", verdict.Info, fmt.Sprintf("handshake with target SNI failed: %s", f.Target.Err))
}

// canSet reports whether a probe may set the verdict type — true only while no
// stronger interference has been concluded.
func canSet(t verdict.Type) bool {
	return t == verdict.OK || t == verdict.Inconclusive || t == ""
}
