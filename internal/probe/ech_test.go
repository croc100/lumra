package probe

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/croc100/lumra/internal/verdict"
)

// buildHTTPSRDATA crafts an HTTPS/SVCB RDATA with an optional ech SvcParam.
func buildHTTPSRDATA(priority uint16, withECH []byte) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint16(b, priority)
	b = append(b, 0) // root TargetName (single zero label)
	// An alpn param (key 1) before ech to exercise ordered skipping.
	b = binary.BigEndian.AppendUint16(b, 1) // key alpn
	b = binary.BigEndian.AppendUint16(b, 3) // len
	b = append(b, 2, 'h', '3')              // alpn list
	if withECH != nil {
		b = binary.BigEndian.AppendUint16(b, 5) // key ech
		b = binary.BigEndian.AppendUint16(b, uint16(len(withECH)))
		b = append(b, withECH...)
	}
	return b
}

func TestECHFromSvcParams(t *testing.T) {
	want := []byte{0xFE, 0x0D, 0x00, 0x41, 0x99}
	rdata := buildHTTPSRDATA(1, want)
	got, ok := echFromSvcParams(rdata)
	if !ok {
		t.Fatal("expected to find an ech SvcParam")
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ech value = %x, want %x", got, want)
	}
}

func TestECHFromSvcParamsAbsent(t *testing.T) {
	rdata := buildHTTPSRDATA(1, nil)
	if _, ok := echFromSvcParams(rdata); ok {
		t.Fatal("no ech param present, but one was reported")
	}
}

func TestECHFromSvcParamsTruncated(t *testing.T) {
	// Claim a 100-byte ech value but supply only a few bytes.
	var b []byte
	b = binary.BigEndian.AppendUint16(b, 1) // priority
	b = append(b, 0)                        // root target
	b = binary.BigEndian.AppendUint16(b, 5) // key ech
	b = binary.BigEndian.AppendUint16(b, 100)
	b = append(b, 1, 2, 3)
	if _, ok := echFromSvcParams(b); ok {
		t.Fatal("truncated SvcParam must not be accepted")
	}
}

func TestClassifyECH(t *testing.T) {
	ok := versionAttempt{HandshakeOK: true, Negotiated: 0x0304}
	reset := versionAttempt{Reset: true}
	timeout := versionAttempt{Timeout: true}

	if _, blocked := classifyECH(ok, reset); !blocked {
		t.Error("plain OK + ECH reset should be ECH blocking")
	}
	if _, blocked := classifyECH(ok, ok); blocked {
		t.Error("both arms OK should not be ECH blocking")
	}
	if _, blocked := classifyECH(reset, reset); blocked {
		t.Error("no plain baseline should not assert ECH blocking")
	}
	if _, blocked := classifyECH(ok, timeout); blocked {
		t.Error("a timeout is not a deliberate reset")
	}
}

func TestECHContribute(t *testing.T) {
	v := &verdict.Verdict{Target: "example.com", Type: verdict.OK}
	f := &ECHFinding{
		Domain: "example.com", IP: "203.0.113.1", HasConfig: true,
		Plain: versionAttempt{HandshakeOK: true, Negotiated: 0x0304},
		ECH:   versionAttempt{Reset: true},
	}
	f.Contribute(v)
	if v.Type != verdict.ECHBlocking {
		t.Fatalf("type = %q, want ECH_BLOCKING", v.Type)
	}
	if verdict.NatureOf(v.Type) != verdict.NatureSurveillance {
		t.Fatal("ECH blocking should fold to surveillance nature")
	}

	// No config advertised: informational only, no verdict change.
	v2 := &verdict.Verdict{Target: "example.com", Type: verdict.OK}
	(&ECHFinding{Domain: "example.com", HasConfig: false}).Contribute(v2)
	if v2.Type != verdict.OK || v2.Evidence[0].Outcome != verdict.Info {
		t.Fatalf("no-config case mishandled: %+v", v2)
	}
}
