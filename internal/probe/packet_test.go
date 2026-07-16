package probe

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestTCPChecksumValid(t *testing.T) {
	src := net.ParseIP("192.0.2.10")
	dst := net.ParseIP("198.51.100.20")
	seg := buildTCPSegment(src, dst, 40000, 443, 0xDEADBEEF, tcpSYN, 65535)

	// A correct checksum makes the pseudo-header + segment sum to zero.
	if got := tcpChecksum(src, dst, seg); got != 0 {
		t.Fatalf("recomputed checksum over signed segment = %#04x, want 0", got)
	}
	if seg[13] != tcpSYN {
		t.Errorf("flags byte = %#02x, want SYN", seg[13])
	}
	if sp := binary.BigEndian.Uint16(seg[0:2]); sp != 40000 {
		t.Errorf("source port = %d, want 40000", sp)
	}
}

func TestParseIPv4TCP(t *testing.T) {
	// Hand-build an IPv4 header (TTL 54) wrapping a SYN/ACK from 203.0.113.5:443.
	src := net.ParseIP("203.0.113.5")
	dst := net.ParseIP("192.0.2.10")
	seg := buildTCPSegment(src, dst, 443, 40000, 1, tcpSYN|tcpACK, 65535)

	ip := make([]byte, 20)
	ip[0] = 0x45 // IPv4, IHL 5
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(seg)))
	ip[8] = 54 // TTL
	ip[9] = protoTCP
	copy(ip[12:16], src.To4())
	copy(ip[16:20], dst.To4())

	pkt := append(ip, seg...)
	got, ok := parseIPv4TCP(pkt)
	if !ok {
		t.Fatal("parseIPv4TCP returned ok=false for a valid packet")
	}
	if got.TTL != 54 {
		t.Errorf("TTL = %d, want 54", got.TTL)
	}
	if !got.SrcIP.Equal(src) {
		t.Errorf("SrcIP = %v, want %v", got.SrcIP, src)
	}
	if got.SrcPort != 443 || got.DstPort != 40000 {
		t.Errorf("ports = %d->%d, want 443->40000", got.SrcPort, got.DstPort)
	}
	if !got.has(tcpSYN) || !got.has(tcpACK) || got.has(tcpRST) {
		t.Errorf("flags = %#02x, want SYN+ACK", got.Flags)
	}
}

func TestParseIPv4TCPRejects(t *testing.T) {
	if _, ok := parseIPv4TCP([]byte{0x45, 0, 0}); ok {
		t.Error("short packet accepted")
	}
	udp := make([]byte, 40)
	udp[0] = 0x45
	udp[9] = 17 // UDP
	if _, ok := parseIPv4TCP(udp); ok {
		t.Error("non-TCP packet accepted")
	}
}
