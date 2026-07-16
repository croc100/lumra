package probe

import (
	"encoding/binary"
	"net"
)

// TCP flag bits, as they sit in byte 13 of the TCP header.
const (
	tcpFIN uint8 = 1 << 0
	tcpSYN uint8 = 1 << 1
	tcpRST uint8 = 1 << 2
	tcpPSH uint8 = 1 << 3
	tcpACK uint8 = 1 << 4
)

const protoTCP = 6

// checksum16 is the 16-bit one's-complement sum used by IP and TCP.
func checksum16(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// tcpChecksum computes the TCP checksum over the IPv4 pseudo-header and segment.
// The segment's own checksum field must be zero on entry.
func tcpChecksum(src, dst net.IP, segment []byte) uint16 {
	pseudo := make([]byte, 12+len(segment))
	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[9] = protoTCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(segment)))
	copy(pseudo[12:], segment)
	return checksum16(pseudo)
}

// buildTCPSegment marshals a bare (no-options) TCP header with a valid checksum.
// It carries no IP header: on Linux a SOCK_RAW/IPPROTO_TCP send socket lets the
// kernel prepend the IP header and route it, so only the segment is crafted.
func buildTCPSegment(src, dst net.IP, sport, dport uint16, seq uint32, flags uint8, window uint16) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	binary.BigEndian.PutUint32(b[4:8], seq)
	// ack (8:12) stays zero
	b[12] = 5 << 4 // data offset: 5 32-bit words, no options
	b[13] = flags
	binary.BigEndian.PutUint16(b[14:16], window)
	// checksum (16:18) zero while computing, urgent pointer (18:20) zero
	binary.BigEndian.PutUint16(b[16:18], tcpChecksum(src, dst, b))
	return b
}

// tcpPacket is the subset of an observed IPv4/TCP packet that RST attribution
// needs: the IP TTL (distance signal) plus the flow's addresses and flags.
type tcpPacket struct {
	TTL     uint8
	SrcIP   net.IP
	SrcPort uint16
	DstPort uint16
	Flags   uint8
}

func (p tcpPacket) has(flag uint8) bool { return p.Flags&flag != 0 }

// parseIPv4TCP reads a raw inbound packet that begins with the IPv4 header (as a
// SOCK_RAW/IPPROTO_TCP recv delivers). It returns ok=false for anything that is
// not a well-formed IPv4 TCP packet.
func parseIPv4TCP(pkt []byte) (tcpPacket, bool) {
	if len(pkt) < 20 {
		return tcpPacket{}, false
	}
	if pkt[0]>>4 != 4 {
		return tcpPacket{}, false // not IPv4
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+20 {
		return tcpPacket{}, false
	}
	if pkt[9] != protoTCP {
		return tcpPacket{}, false
	}
	tcp := pkt[ihl:]
	return tcpPacket{
		TTL:     pkt[8],
		SrcIP:   net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15]),
		SrcPort: binary.BigEndian.Uint16(tcp[0:2]),
		DstPort: binary.BigEndian.Uint16(tcp[2:4]),
		Flags:   tcp[13],
	}, true
}
