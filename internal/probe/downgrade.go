package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/croc100/lumra/internal/verdict"
)

// A surveillance middlebox that wants to read a session's SNI and certificate
// must keep the handshake in TLS 1.2, where both travel in cleartext; TLS 1.3
// encrypts the certificate and enables ECH, blinding a passive tap. Forcing the
// path down to 1.2 is therefore an interception signal, not a block. Downgrade
// probes for it by comparing an unconstrained handshake against a 1.3-only one.

// versionAttempt records one handshake pinned to a version policy.
type versionAttempt struct {
	Negotiated  uint16 // tls.VersionTLS1x actually negotiated, 0 if none
	HandshakeOK bool
	Reset       bool // TCP reset — the middlebox signature
	Timeout     bool
	Err         string
}

// DowngradeFinding compares a default (1.3-preferring) handshake against one
// that requires TLS 1.3, both to the same ground-truth IP.
type DowngradeFinding struct {
	Domain  string
	IP      string
	Default versionAttempt // MaxVersion unset: negotiates the best both sides allow
	Forced  versionAttempt // MinVersion pinned to TLS 1.3
}

// Downgrade probes ip:443 twice to detect a middlebox stripping TLS 1.3. ip
// should be a ground-truth address so a poisoned answer cannot skew the result.
func Downgrade(ctx context.Context, domain, ip string) *DowngradeFinding {
	return &DowngradeFinding{
		Domain:  domain,
		IP:      ip,
		Default: versionHandshake(ctx, ip, domain, 0),
		Forced:  versionHandshake(ctx, ip, domain, tls.VersionTLS13),
	}
}

// versionHandshake dials ip:443 with sni. When minVer is non-zero it pins both
// MinVersion and MaxVersion to it, so a failure isolates that version's fate.
func versionHandshake(ctx context.Context, ip, sni string, minVer uint16) versionAttempt {
	var a versionAttempt
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		classifyVersionErr(&a, err)
		return a
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	cfg := &tls.Config{ServerName: sni, InsecureSkipVerify: true}
	if minVer != 0 {
		cfg.MinVersion, cfg.MaxVersion = minVer, minVer
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		classifyVersionErr(&a, err)
		return a
	}
	a.HandshakeOK = true
	a.Negotiated = tc.ConnectionState().Version
	return a
}

// classifyVersionErr splits a handshake failure into a TCP reset (middlebox) and
// everything else (timeout or a server-sent alert). The reset-vs-alert split is
// the crux: a server that simply won't speak 1.3 sends an alert, while a
// middlebox stripping 1.3 tears the connection down with a reset.
func classifyVersionErr(a *versionAttempt, err error) {
	a.Err = err.Error()
	if isTimeout(err) {
		a.Timeout = true
		return
	}
	if isReset(err) {
		a.Reset = true
	}
}

// classifyDowngrade decides, from the two arms, whether TLS 1.3 is being
// stripped on the path. Pure — unit-tested. It returns ok=false when there is
// no downgrade signal (the common case). The signal requires that the ordinary
// handshake works but lands on ≤1.2 AND the 1.3-only arm is reset: a server that
// merely lacks 1.3 answers the forced arm with an alert, not a reset.
func classifyDowngrade(def, forced versionAttempt) (verdict.Confidence, bool) {
	if !def.HandshakeOK || def.Negotiated == 0 || def.Negotiated >= tls.VersionTLS13 {
		return "", false // no working 1.2 session, or 1.3 already succeeds → nothing stripped
	}
	if forced.Reset {
		// 1.2 works, 1.3 is torn down mid-path → active stripping.
		return verdict.Medium, true
	}
	return "", false
}

// Contribute folds the downgrade finding into the verdict.
func (f *DowngradeFinding) Contribute(v *verdict.Verdict) {
	conf, stripped := classifyDowngrade(f.Default, f.Forced)
	if !stripped {
		if f.Default.HandshakeOK {
			v.Add("TLSv", verdict.Pass, fmt.Sprintf(
				"negotiated %s with target SNI on %s", versionName(f.Default.Negotiated), f.IP))
		}
		return
	}
	v.Add("TLSv", verdict.Fail, fmt.Sprintf(
		"default handshake lands on %s while a TLS 1.3-only handshake to %s is reset — 1.3 is being stripped on the path",
		versionName(f.Default.Negotiated), f.IP))
	if canSet(v.Type) {
		v.Type = verdict.TLSDowngrade
		v.Confidence = conf
		v.Cause = "A normal handshake completes only at TLS 1.2, but forcing TLS 1.3 is reset " +
			"by a middlebox on the path. TLS 1.3 encrypts the certificate and enables ECH; " +
			"stripping it back to 1.2 keeps the SNI and certificate readable — the signature " +
			"of an interception/surveillance middlebox, not a block."
	}
}

// versionName renders a TLS version constant for evidence lines.
func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case 0:
		return "no handshake"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
