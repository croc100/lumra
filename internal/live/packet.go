package live

import (
	"encoding/binary"
	"time"
)

// This file holds the portable, OS-independent packet path: given a raw IP
// packet (v4 or v6) it extracts the TLS handshake metadata and DNS answers Lumra
// reasons about, and emits tap events. It is deliberately free of any syscall or
// framing concern so it is shared by every capture backend — the Linux AF_PACKET
// tap (which strips an Ethernet header first) and the TUN/VPN source (desktop and
// mobile, which deliver raw IP packets already). The mobile VPN tunnel wires
// straight into dispatcher.handle; nothing here changes per platform.

const flagRST = 1 << 2

// flowKey identifies one connection by the server IP and the client's ephemeral
// port, stable across both directions of the flow. The IP is held in a 16-byte
// field so IPv4 and IPv6 share the same key type (IPv4 occupies the first four
// bytes, the rest zero).
type flowKey struct {
	serverIP [16]byte
	clientPt uint16
}

// flowState carries the per-connection data the tap accumulates: the domain from
// the ClientHello and reassemblers for each direction's handshake stream. chre
// rebuilds the client's ClientHello (which may span several TCP segments); re
// rebuilds the server's handshake (ServerHello + certificate).
type flowState struct {
	domain string
	chre   hsReassembler // client→server: ClientHello reassembly (SNI)
	re     hsReassembler // server→client: ServerHello/Certificate reassembly
}

// l4 is the parsed subset of an IP packet the dispatcher needs. IP addresses are
// held as 16 bytes for both families (IPv4 in the first four bytes).
type l4 struct {
	srcIP, dstIP     [16]byte
	srcPort, dstPort uint16
	proto            byte
	flags            byte   // TCP flags
	payload          []byte // L4 payload (TLS records or DNS message)
}

const (
	protoTCP = 6
	protoUDP = 17
)

// dispatcher turns raw IP packets into tap events. It owns the per-flow state,
// so a single capture goroutine drives it.
type dispatcher struct {
	flows map[flowKey]*flowState
	emit  func(Event)
}

func newDispatcher(emit func(Event)) *dispatcher {
	return &dispatcher{flows: make(map[flowKey]*flowState), emit: emit}
}

// handle parses one raw IP packet (v4 or v6) and emits any events it yields.
func (d *dispatcher) handle(ip []byte, now time.Time) {
	p, ok := parseIPPacket(ip)
	if !ok {
		return
	}
	switch p.proto {
	case protoTCP:
		d.handleTLS(p, now)
	case protoUDP:
		// A DNS reply arrives from source port 53; that is all we passively read.
		if p.srcPort == 53 {
			d.handleDNS(p, now)
		}
	}
}

// handleTLS attributes a TCP segment to its flow and reads the SNI, negotiated
// version, certificate, and resets from the (reassembled) handshake.
func (d *dispatcher) handleTLS(p l4, now time.Time) {
	switch {
	case p.dstPort == 443: // outbound to a server
		key := flowKey{p.dstIP, p.srcPort}
		st := d.flows[key]
		if st == nil {
			st = &flowState{}
			d.flows[key] = st
		}
		if st.domain != "" {
			return // SNI already read for this flow
		}
		// Reassemble the ClientHello across segments, then read its SNI.
		for _, msg := range st.chre.Feed(p.payload) {
			if sni, ok := clientHelloSNI(msg); ok {
				st.domain = sni
				d.emit(Event{Kind: ClientHello, Domain: sni, At: now})
				break
			}
		}
		// Not a ClientHello flow (or unreadable): drop the pending entry so a
		// non-TLS connection on :443 does not leak an empty flow.
		if st.domain == "" && st.chre.done {
			delete(d.flows, key)
		}
	case p.srcPort == 443: // inbound from a server
		key := flowKey{p.srcIP, p.dstPort}
		st := d.flows[key]
		if st == nil || st.domain == "" {
			return // no ClientHello attributed to this flow yet; nothing to attribute
		}
		if p.flags&flagRST != 0 {
			d.emit(Event{Kind: Reset, Domain: st.domain, At: now})
			delete(d.flows, key)
			return
		}
		for _, msg := range st.re.Feed(p.payload) {
			switch msg[0] {
			case 2: // ServerHello
				if v, ok := parseServerHelloMsg(msg); ok {
					d.emit(Event{Kind: ServerHello, Domain: st.domain, Version: v, At: now})
				}
			case 11: // Certificate (TLS 1.2 cleartext) — passive MITM check
				if ders, ok := extractCertificates(msg); ok {
					if subj, untrusted, ok := inspectChain(ders, st.domain); ok {
						d.emit(Event{Kind: Cert, Domain: st.domain, Untrusted: untrusted, Subject: subj, At: now})
					}
				}
			}
		}
	}
}

// handleDNS reads a DNS reply and, when its answer bears a censorship signature
// (a sinkhole/bogon address for a public name), emits a DNS event.
func (d *dispatcher) handleDNS(p l4, now time.Time) {
	name, ips, ok := parseDNSReply(p.payload)
	if !ok || name == "" {
		return
	}
	if reason, bad := suspiciousAnswer(ips); bad {
		d.emit(Event{Kind: DNS, Domain: name, Suspicious: true, Reason: reason, At: now})
	}
}

// parseEthernet returns the IP payload of an Ethernet II frame carrying IPv4 or
// IPv6, or ok=false for anything else. Used by the AF_PACKET backend.
func parseEthernet(b []byte) ([]byte, bool) {
	if len(b) < 14 {
		return nil, false
	}
	switch binary.BigEndian.Uint16(b[12:14]) {
	case 0x0800, 0x86DD: // IPv4, IPv6
		return b[14:], true
	default:
		return nil, false
	}
}

// parseIPPacket dispatches on the IP version nibble to the v4 or v6 parser, so
// every backend can feed a raw IP packet of either family.
func parseIPPacket(ip []byte) (l4, bool) {
	if len(ip) < 1 {
		return l4{}, false
	}
	switch ip[0] >> 4 {
	case 4:
		return parseIPv4Packet(ip)
	case 6:
		return parseIPv6Packet(ip)
	default:
		return l4{}, false
	}
}

// parseIPv4Packet parses an IPv4 packet carrying TCP or UDP. Bounds are checked
// at every step against raw wire data.
func parseIPv4Packet(ip []byte) (l4, bool) {
	if len(ip) < 20 || ip[0]>>4 != 4 {
		return l4{}, false
	}
	proto := ip[9]
	if proto != protoTCP && proto != protoUDP {
		return l4{}, false
	}
	ihl := int(ip[0]&0x0f) * 4
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if ihl < 20 || len(ip) < ihl || totalLen < ihl || totalLen > len(ip) {
		return l4{}, false
	}
	var f l4
	f.proto = proto
	copy(f.srcIP[:], ip[12:16])
	copy(f.dstIP[:], ip[16:20])
	l4b := ip[ihl:totalLen]

	if proto == protoUDP {
		if len(l4b) < 8 {
			return l4{}, false
		}
		f.srcPort = binary.BigEndian.Uint16(l4b[0:2])
		f.dstPort = binary.BigEndian.Uint16(l4b[2:4])
		f.payload = l4b[8:]
		return f, true
	}
	// TCP
	if len(l4b) < 20 {
		return l4{}, false
	}
	dataOff := int(l4b[12]>>4) * 4
	if dataOff < 20 || len(l4b) < dataOff {
		return l4{}, false
	}
	f.srcPort = binary.BigEndian.Uint16(l4b[0:2])
	f.dstPort = binary.BigEndian.Uint16(l4b[2:4])
	f.flags = l4b[13]
	f.payload = l4b[dataOff:]
	return f, true
}

// parseIPv6Packet parses an IPv6 packet carrying TCP or UDP directly (no
// extension headers). The fixed 40-byte header makes this simpler than IPv4;
// packets that carry extension headers (hop-by-hop, routing, fragmentation) are
// skipped rather than mis-parsed — they are rare on the TLS/DNS flows Lumra
// watches, and guessing past them risks reading the wrong offset.
func parseIPv6Packet(ip []byte) (l4, bool) {
	const hdr = 40
	if len(ip) < hdr || ip[0]>>4 != 6 {
		return l4{}, false
	}
	proto := ip[6] // next header
	if proto != protoTCP && proto != protoUDP {
		return l4{}, false
	}
	payloadLen := int(binary.BigEndian.Uint16(ip[4:6]))
	end := hdr + payloadLen
	if payloadLen == 0 || end > len(ip) {
		// Jumbograms (payloadLen 0) and truncated captures: don't guess.
		return l4{}, false
	}
	var f l4
	f.proto = proto
	copy(f.srcIP[:], ip[8:24])
	copy(f.dstIP[:], ip[24:40])
	l4b := ip[hdr:end]

	if proto == protoUDP {
		if len(l4b) < 8 {
			return l4{}, false
		}
		f.srcPort = binary.BigEndian.Uint16(l4b[0:2])
		f.dstPort = binary.BigEndian.Uint16(l4b[2:4])
		f.payload = l4b[8:]
		return f, true
	}
	// TCP
	if len(l4b) < 20 {
		return l4{}, false
	}
	dataOff := int(l4b[12]>>4) * 4
	if dataOff < 20 || len(l4b) < dataOff {
		return l4{}, false
	}
	f.srcPort = binary.BigEndian.Uint16(l4b[0:2])
	f.dstPort = binary.BigEndian.Uint16(l4b[2:4])
	f.flags = l4b[13]
	f.payload = l4b[dataOff:]
	return f, true
}
