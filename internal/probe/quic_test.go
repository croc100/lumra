package probe

import (
	"encoding/binary"
	"testing"

	"github.com/croc100/lumra/internal/verdict"
)

func TestAdvertisesHTTP3(t *testing.T) {
	// alpn = h3, h2
	alpn := []byte{2, 'h', '3', 2, 'h', '2'}
	var rdata []byte
	rdata = binary.BigEndian.AppendUint16(rdata, 1) // priority
	rdata = append(rdata, 0)                        // root target
	rdata = binary.BigEndian.AppendUint16(rdata, 1) // key alpn
	rdata = binary.BigEndian.AppendUint16(rdata, uint16(len(alpn)))
	rdata = append(rdata, alpn...)
	if !advertisesHTTP3(rdata) {
		t.Fatal("h3 in alpn not detected")
	}

	// alpn = h2 only
	alpn2 := []byte{2, 'h', '2'}
	var r2 []byte
	r2 = binary.BigEndian.AppendUint16(r2, 1)
	r2 = append(r2, 0)
	r2 = binary.BigEndian.AppendUint16(r2, 1)
	r2 = binary.BigEndian.AppendUint16(r2, uint16(len(alpn2)))
	r2 = append(r2, alpn2...)
	if advertisesHTTP3(r2) {
		t.Fatal("h2-only alpn should not report h3")
	}
}

func TestClassifyQUIC(t *testing.T) {
	if _, blocked := classifyQUIC(true, true, false); !blocked {
		t.Error("h3-advertised + TCP open + no QUIC reply should be a block")
	}
	if _, blocked := classifyQUIC(true, true, true); blocked {
		t.Error("QUIC reply present should not be a block")
	}
	if _, blocked := classifyQUIC(false, true, false); blocked {
		t.Error("no h3 advertised should never be asserted as a block")
	}
	if _, blocked := classifyQUIC(true, false, false); blocked {
		t.Error("no TCP baseline should not assert a QUIC block")
	}
}

func TestQUICResponseDetection(t *testing.T) {
	// A long-header packet (high bit set) is a QUIC response.
	if !isQUICResponse([]byte{0x80, 0, 0, 0, 0}) {
		t.Error("long-header packet should be recognised")
	}
	// A short-header / non-QUIC datagram is not.
	if isQUICResponse([]byte{0x40, 1, 2, 3, 4}) {
		t.Error("short-header packet should not be a VN response")
	}
	if isQUICResponse([]byte{0x80}) {
		t.Error("too-short datagram should be rejected")
	}
}

func TestVersionNegotiationTriggerShape(t *testing.T) {
	pkt := versionNegotiationTrigger()
	if len(pkt) < 1200 {
		t.Fatalf("VN trigger must be padded to >=1200 bytes, got %d", len(pkt))
	}
	if pkt[0]&0x80 == 0 {
		t.Fatal("VN trigger must be a long-header packet")
	}
	if v := binary.BigEndian.Uint32(pkt[1:5]); v != 0x1a1a1a1a {
		t.Fatalf("VN trigger version = %#x, want a reserved version", v)
	}
}

func TestQUICContribute(t *testing.T) {
	v := &verdict.Verdict{Target: "example.com", Type: verdict.OK}
	(&QUICFinding{Domain: "example.com", IP: "203.0.113.1", AdvertisesH3: true, TCPOpen: true, QUICReply: false}).Contribute(v)
	if v.Type != verdict.QUICBlocking {
		t.Fatalf("type = %q, want QUIC_BLOCKING", v.Type)
	}
	if verdict.NatureOf(v.Type) != verdict.NatureDegradation {
		t.Fatal("QUIC blocking should fold to degradation nature")
	}

	// Reachable QUIC → pass, no verdict change.
	v2 := &verdict.Verdict{Target: "example.com", Type: verdict.OK}
	(&QUICFinding{Domain: "example.com", AdvertisesH3: true, TCPOpen: true, QUICReply: true}).Contribute(v2)
	if v2.Type != verdict.OK || v2.Evidence[0].Outcome != verdict.Pass {
		t.Fatalf("reachable QUIC mishandled: %+v", v2)
	}
}
