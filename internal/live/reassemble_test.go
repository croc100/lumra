package live

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// selfSignedDER returns a self-signed certificate (DER) for cn — a stand-in for
// a middlebox's substituted certificate, which will not chain to any system root.
func selfSignedDER(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// certificateMessage wraps DERs in a TLS 1.2 Certificate handshake message.
func certificateMessage(ders ...[]byte) []byte {
	var list []byte
	for _, d := range ders {
		list = append(list, byte(len(d)>>16), byte(len(d)>>8), byte(len(d)))
		list = append(list, d...)
	}
	body := append([]byte{byte(len(list) >> 16), byte(len(list) >> 8), byte(len(list))}, list...)
	return append([]byte{11, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

// recordWrap frames a handshake message in a TLS record (type 22).
func recordWrap(msg []byte) []byte {
	return append([]byte{22, 3, 3, byte(len(msg) >> 8), byte(len(msg))}, msg...)
}

func TestInspectChainUntrusted(t *testing.T) {
	der := selfSignedDER(t, "evil.example")
	subj, untrusted, ok := inspectChain([][]byte{der}, "evil.example")
	if !ok || !untrusted {
		t.Fatalf("self-signed cert should be untrusted: ok=%v untrusted=%v", ok, untrusted)
	}
	if subj != "evil.example" {
		t.Errorf("subject = %q, want evil.example", subj)
	}
}

func TestReassembleCertificateSplitAcrossSegments(t *testing.T) {
	der := selfSignedDER(t, "bank.example")
	// A ServerHello record followed by a Certificate record, both handshake.
	sh := recordWrap(buildServerHello(0x0303, nil)[5:]) // reuse SH body, rewrap cleanly
	stream := append(sh, recordWrap(certificateMessage(der))...)

	var r hsReassembler
	var got [][]byte
	// Feed one byte at a time — the worst-case segmentation.
	for i := 0; i < len(stream); i++ {
		got = append(got, r.Feed(stream[i:i+1])...)
	}

	var sawSH, sawCert bool
	for _, msg := range got {
		switch msg[0] {
		case 2:
			sawSH = true
		case 11:
			sawCert = true
			ders, ok := extractCertificates(msg)
			if !ok || len(ders) != 1 {
				t.Fatalf("extractCertificates failed: ok=%v n=%d", ok, len(ders))
			}
			if _, untrusted, _ := inspectChain(ders, "bank.example"); !untrusted {
				t.Error("reassembled substituted cert should read untrusted")
			}
		}
	}
	if !sawSH || !sawCert {
		t.Fatalf("reassembly missed messages: SH=%v Cert=%v", sawSH, sawCert)
	}
}

func TestReassemblerStopsOnNonHandshake(t *testing.T) {
	var r hsReassembler
	// An application_data record (type 23) means the handshake is over/encrypted.
	appData := []byte{23, 3, 3, 0, 2, 0xAA, 0xBB}
	if msgs := r.Feed(appData); len(msgs) != 0 {
		t.Errorf("app-data should yield no handshake messages, got %d", len(msgs))
	}
	if !r.done {
		t.Error("reassembler should be done after a non-handshake record")
	}
}

func TestReassemblerCapsBuffer(t *testing.T) {
	var r hsReassembler
	// A record header claiming a huge length must not make us buffer unbounded.
	r.Feed(append([]byte{22, 3, 3, 0xFF, 0xFF}, make([]byte, maxHandshakeBuffer+10)...))
	if !r.done {
		t.Error("reassembler should stop once the buffer cap is exceeded")
	}
}
