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
	cert        *x509.Certificate
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
	}
	return a
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
	// Strongest signal: target SNI is reset while a benign SNI is accepted on the
	// same IP. That isolates the reset to the SNI value → SNI-based filtering.
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

	// Both SNIs reset: not SNI-specific — likely IP-level blocking. Record as
	// context; the RST/TTL probe will attribute it.
	if f.Target.Reset && f.Benign.Reset {
		v.Add("TLS", verdict.Info, fmt.Sprintf(
			"both target and benign SNI reset on %s — not SNI-specific (see RST probe)", f.IP))
		return
	}

	if f.Target.HandshakeOK {
		v.Add("TLS", verdict.Pass, fmt.Sprintf("handshake OK with target SNI on %s", f.IP))
		return
	}

	if !f.Target.Connected {
		v.Add("TLS", verdict.Info, fmt.Sprintf("TCP to %s:443 failed (%s)", f.IP, f.Target.Err))
		return
	}
	v.Add("TLS", verdict.Info, fmt.Sprintf("handshake with target SNI failed: %s", f.Target.Err))
}
