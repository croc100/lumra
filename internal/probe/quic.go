package probe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"

	"github.com/croc100/lumra/internal/verdict"
)

// QUIC carries HTTP/3, and censors increasingly block UDP/443 wholesale to force
// traffic back onto TCP, where SNI filtering and RST injection still work. Naively
// "no QUIC response" is ambiguous — plenty of servers simply don't run QUIC, and
// benign firewalls drop UDP. Lumra removes that ambiguity: it only concludes QUIC
// is being blocked when the target's own DNS HTTPS record advertises HTTP/3 (so
// the server WOULD answer QUIC) yet a QUIC probe to UDP/443 draws no response
// while TCP/443 is reachable. That three-way agreement is a real block, not a
// server that never spoke QUIC.

// QUICFinding records the QUIC/HTTP3 reachability comparison.
type QUICFinding struct {
	Domain       string
	IP           string
	AdvertisesH3 bool // the target's HTTPS record lists the h3 ALPN
	TCPOpen      bool // TCP/443 completes a connection (baseline reachability)
	QUICReply    bool // a QUIC packet came back from UDP/443
}

// QUIC probes UDP/443 for HTTP/3 reachability against ip, using the target's
// advertised ALPN to avoid false positives. ip should be a ground-truth address.
func QUIC(ctx context.Context, domain, ip string) *QUICFinding {
	f := &QUICFinding{Domain: domain, IP: ip}
	if rdata, ok := fetchHTTPSRecord(ctx, domain); ok {
		f.AdvertisesH3 = advertisesHTTP3(rdata)
	}
	f.TCPOpen = tcpReachable(ctx, ip)
	f.QUICReply = quicReachable(ctx, ip)
	return f
}

// tcpReachable reports whether a TCP connection to ip:443 completes.
func tcpReachable(ctx context.Context, ip string) bool {
	d := net.Dialer{Timeout: 4 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// quicReachable sends a QUIC Initial with an unsupported version to elicit a
// Version Negotiation packet and reports whether any QUIC response returns. A VN
// response needs no valid packet protection — the server replies to any
// long-header packet whose version it does not know — so this stays dependency-
// free while still proving UDP/443 carries QUIC to the server end to end.
func quicReachable(ctx context.Context, ip string) bool {
	pkt := versionNegotiationTrigger()
	d := net.Dialer{Timeout: 4 * time.Second}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return false
	}
	defer conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	buf := make([]byte, 1500)
	// Two sends: the first datagram can be lost, and QUIC has no retransmit here.
	for i := 0; i < 2 && time.Now().Before(deadline); i++ {
		if _, err := conn.Write(pkt); err != nil {
			return false
		}
		_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err == nil && isQUICResponse(buf[:n]) {
			return true
		}
	}
	return false
}

// versionNegotiationTrigger builds a QUIC long-header packet with a reserved
// (unsupported) version, padded to the 1200-byte minimum that servers require
// before answering, so it reliably provokes a Version Negotiation response.
func versionNegotiationTrigger() []byte {
	const minDatagram = 1200
	pkt := make([]byte, 0, minDatagram)
	// First byte: long header (0x80) + fixed bit (0x40); low bits are ignored by
	// a server that does not recognise the version.
	pkt = append(pkt, 0xC0)
	// Version: 0x?a?a?a?a is a reserved pattern that must force VN (RFC 9000 §15).
	pkt = binary.BigEndian.AppendUint32(pkt, 0x1a1a1a1a)
	// Destination and Source Connection IDs, 8 random bytes each.
	dcid := make([]byte, 8)
	scid := make([]byte, 8)
	_, _ = rand.Read(dcid)
	_, _ = rand.Read(scid)
	pkt = append(pkt, 8)
	pkt = append(pkt, dcid...)
	pkt = append(pkt, 8)
	pkt = append(pkt, scid...)
	// Pad to the anti-amplification minimum.
	if len(pkt) < minDatagram {
		pkt = append(pkt, make([]byte, minDatagram-len(pkt))...)
	}
	return pkt
}

// isQUICResponse reports whether a datagram looks like a QUIC packet from the
// server — a long-header packet (high bit set). A Version Negotiation packet
// additionally carries an all-zero version, but any QUIC long-header reply is
// enough to prove the path reached a QUIC endpoint.
func isQUICResponse(b []byte) bool {
	return len(b) >= 5 && b[0]&0x80 != 0
}

// classifyQUIC decides whether HTTP/3 is being blocked on the path. Pure — unit
// tested. It concludes a block only when the server advertises h3, TCP is open,
// and QUIC drew no reply: the target would speak QUIC but UDP/443 is not getting
// through. Any other combination is not asserted.
func classifyQUIC(advertisesH3, tcpOpen, quicReply bool) (verdict.Confidence, bool) {
	if advertisesH3 && tcpOpen && !quicReply {
		return verdict.Medium, true
	}
	return "", false
}

// Contribute folds the QUIC finding into the verdict.
func (f *QUICFinding) Contribute(v *verdict.Verdict) {
	conf, blocked := classifyQUIC(f.AdvertisesH3, f.TCPOpen, f.QUICReply)
	if blocked {
		v.Add("QUIC", verdict.Fail, "target advertises HTTP/3 and TCP/443 is open, but a QUIC probe to UDP/443 drew no response — QUIC/HTTP3 is being blocked, forcing traffic onto filterable TCP")
		if canSet(v.Type) {
			v.Type = verdict.QUICBlocking
			v.Confidence = conf
			v.Cause = "The target offers HTTP/3 (advertised in DNS) and its TCP port is reachable, " +
				"yet UDP/443 carries no QUIC response. Blocking QUIC forces the connection back onto " +
				"TCP, where the SNI stays filterable and RSTs can be injected — a deliberate downgrade " +
				"of the modern, harder-to-censor transport."
		}
		return
	}
	switch {
	case f.QUICReply:
		v.Add("QUIC", verdict.Pass, "QUIC/HTTP3 reachable on UDP/443")
	case f.AdvertisesH3:
		v.Add("QUIC", verdict.Info, "target advertises HTTP/3 but QUIC did not respond (may be blocked or path-filtered; TCP baseline unproven)")
	default:
		v.Add("QUIC", verdict.Info, "target does not advertise HTTP/3 — QUIC reachability not asserted")
	}
}
