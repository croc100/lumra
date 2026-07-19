package live

import (
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"
)

// ipv4 wraps an L4 payload in an IPv4 header for proto (6 TCP, 17 UDP).
func ipv4(proto byte, src, dst [4]byte, l4 []byte) []byte {
	total := 20 + len(l4)
	h := make([]byte, 20)
	h[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(h[2:4], uint16(total))
	h[8] = 64 // TTL
	h[9] = proto
	copy(h[12:16], src[:])
	copy(h[16:20], dst[:])
	return append(h, l4...)
}

// tcpSeg builds a minimal TCP segment (no options) with the given ports/flags.
func tcpSeg(sport, dport uint16, flags byte, payload []byte) []byte {
	t := make([]byte, 20)
	binary.BigEndian.PutUint16(t[0:2], sport)
	binary.BigEndian.PutUint16(t[2:4], dport)
	t[12] = 5 << 4 // data offset 5 words
	t[13] = flags
	return append(t, payload...)
}

// udpDatagram builds a UDP datagram with the given ports.
func udpDatagram(sport, dport uint16, payload []byte) []byte {
	u := make([]byte, 8)
	binary.BigEndian.PutUint16(u[0:2], sport)
	binary.BigEndian.PutUint16(u[2:4], dport)
	binary.BigEndian.PutUint16(u[4:6], uint16(8+len(payload)))
	return append(u, payload...)
}

func collect() (*[]Event, func(Event)) {
	var evs []Event
	return &evs, func(e Event) { evs = append(evs, e) }
}

func TestDispatcherTLSClientHello(t *testing.T) {
	client := [4]byte{192, 168, 0, 2}
	server := [4]byte{93, 184, 216, 34}
	hello := realClientHello(t, "bank.example.com")
	pkt := ipv4(protoTCP, client, server, tcpSeg(50000, 443, 0x18, hello))

	evs, emit := collect()
	newDispatcher(emit).handle(pkt, time.Now())
	if len(*evs) != 1 || (*evs)[0].Kind != ClientHello || (*evs)[0].Domain != "bank.example.com" {
		t.Fatalf("expected a ClientHello event for bank.example.com, got %+v", *evs)
	}
}

func TestDispatcherDNSRedirect(t *testing.T) {
	resolver := [4]byte{1, 1, 1, 1}
	client := [4]byte{192, 168, 0, 2}
	reply := dnsReply("blocked.example.com", [4]byte{0, 0, 0, 0})
	pkt := ipv4(protoUDP, resolver, client, udpDatagram(53, 50000, reply))

	evs, emit := collect()
	newDispatcher(emit).handle(pkt, time.Now())
	if len(*evs) != 1 || (*evs)[0].Kind != DNS || !(*evs)[0].Suspicious {
		t.Fatalf("expected a suspicious DNS event, got %+v", *evs)
	}
}

func TestDispatcherIgnoresCleanDNS(t *testing.T) {
	pkt := ipv4(protoUDP, [4]byte{1, 1, 1, 1}, [4]byte{192, 168, 0, 2},
		udpDatagram(53, 50000, dnsReply("ok.example.com", [4]byte{93, 184, 216, 34})))
	evs, emit := collect()
	newDispatcher(emit).handle(pkt, time.Now())
	if len(*evs) != 0 {
		t.Fatalf("clean DNS answer should emit nothing, got %+v", *evs)
	}
}

// oneShotReader returns each packet once (TUN semantics), then io.EOF.
type oneShotReader struct {
	packets [][]byte
	i       int
}

func (r *oneShotReader) Read(p []byte) (int, error) {
	if r.i >= len(r.packets) {
		return 0, io.EOF
	}
	n := copy(p, r.packets[r.i])
	r.i++
	return n, nil
}

func TestTunSourceDispatches(t *testing.T) {
	client := [4]byte{10, 0, 0, 2}
	server := [4]byte{93, 184, 216, 34}
	hello := realClientHello(t, "phone.example.com")
	pkt := ipv4(protoTCP, client, server, tcpSeg(41000, 443, 0x18, hello))

	evs, emit := collect()
	// stripPrefix 0: a mobile provider delivers raw IP with no framing header.
	src := NewTunSource(&oneShotReader{packets: [][]byte{pkt}}, 0)
	_ = src.Run(context.Background(), emit)

	if len(*evs) != 1 || (*evs)[0].Domain != "phone.example.com" {
		t.Fatalf("TunSource should dispatch the ClientHello, got %+v", *evs)
	}
}
