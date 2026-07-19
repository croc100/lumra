package live

import (
	"net/netip"
	"strings"
)

// Passive DNS: Lumra reads DNS replies straight off the wire (UDP source port
// 53) without opening a resolver of its own. It cannot compare against DoH ground
// truth here — that is the active mode's job — so it asserts only what a reply
// proves by itself: a public name answered with a sinkhole/bogon address is the
// classic signature of an injected redirect ("정부가 DNS를 우회"), and needs no
// reference to call. Ordinary answers produce no event.

// parseDNSReply extracts the queried name and any A-record IPv4 answers from a
// DNS reply message. Bounds-checked throughout; ok=false for malformed input or
// a non-reply. Only the first question name is returned.
func parseDNSReply(msg []byte) (name string, ips []string, ok bool) {
	if len(msg) < 12 {
		return "", nil, false
	}
	flags := uint16(msg[2])<<8 | uint16(msg[3])
	if flags&0x8000 == 0 { // QR bit: must be a response
		return "", nil, false
	}
	qd := int(msg[4])<<8 | int(msg[5])
	an := int(msg[6])<<8 | int(msg[7])
	if qd < 1 {
		return "", nil, false
	}
	p := 12

	// Question section: read the first name, then skip QTYPE+QCLASS (4 bytes).
	name, p, ok = readName(msg, p)
	if !ok {
		return "", nil, false
	}
	// Skip remaining questions' fixed fields and any extra questions entirely.
	p += 4
	for i := 1; i < qd; i++ {
		_, p, ok = readName(msg, p)
		if !ok {
			return "", nil, false
		}
		p += 4
	}

	// Answer section: collect A records (TYPE 1, class IN, RDLENGTH 4).
	for i := 0; i < an; i++ {
		_, np, nok := readName(msg, p)
		if !nok || np+10 > len(msg) {
			return name, ips, true // stop at first malformed RR; keep what we have
		}
		typ := int(msg[np])<<8 | int(msg[np+1])
		rdlen := int(msg[np+8])<<8 | int(msg[np+9])
		rd := np + 10
		if rd+rdlen > len(msg) {
			return name, ips, true
		}
		if typ == 1 && rdlen == 4 { // A record
			ip := netip.AddrFrom4([4]byte{msg[rd], msg[rd+1], msg[rd+2], msg[rd+3]})
			ips = append(ips, ip.String())
		}
		p = rd + rdlen
	}
	return name, ips, true
}

// readName decodes a DNS name (with compression pointers) starting at off,
// returning the dotted name and the offset just past the name in the record
// stream. Pointer loops are bounded by a hard jump limit.
func readName(msg []byte, off int) (string, int, bool) {
	var labels []string
	pos := off
	next := -1
	jumps := 0
	for {
		if pos >= len(msg) {
			return "", 0, false
		}
		b := int(msg[pos])
		switch {
		case b == 0:
			pos++
			if next == -1 {
				next = pos
			}
			return strings.Join(labels, "."), next, true
		case b&0xc0 == 0xc0: // compression pointer
			if pos+1 >= len(msg) {
				return "", 0, false
			}
			ptr := (b&0x3f)<<8 | int(msg[pos+1])
			if next == -1 {
				next = pos + 2
			}
			jumps++
			if jumps > 16 {
				return "", 0, false
			}
			pos = ptr
		default: // label
			if pos+1+b > len(msg) {
				return "", 0, false
			}
			labels = append(labels, string(msg[pos+1:pos+1+b]))
			pos += 1 + b
		}
	}
}

// suspiciousAnswer reports whether a set of answer IPs bears an injected-redirect
// signature: a non-empty answer where a resolved address is unroutable for real
// public traffic — loopback, private, link-local, unspecified (0.0.0.0), or a
// documentation/reserved range. Such answers are how censors sinkhole a name.
func suspiciousAnswer(ips []string) (string, bool) {
	for _, s := range ips {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		switch {
		case a.IsUnspecified():
			return "answer points to 0.0.0.0 — a sinkhole, not a real server", true
		case a.IsLoopback():
			return "answer points to loopback (127.0.0.0/8) — a redirect", true
		case a.IsPrivate():
			return "answer points to a private address — a redirect/sinkhole", true
		case a.IsLinkLocalUnicast():
			return "answer points to a link-local address — a redirect", true
		case isReservedDoc(a):
			return "answer points to a reserved/documentation address — a redirect", true
		}
	}
	return "", false
}

// isReservedDoc flags TEST-NET / documentation ranges sometimes used as sinkholes.
func isReservedDoc(a netip.Addr) bool {
	for _, p := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4"} {
		if netip.MustParsePrefix(p).Contains(a) {
			return true
		}
	}
	return false
}
