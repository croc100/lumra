package live

import (
	"crypto/tls"
	"net"
	"testing"
)

// realClientHello captures a genuine ClientHello off the wire by starting a TLS
// client handshake against a pipe and grabbing the first flight. This exercises
// the parser against the exact bytes crypto/tls emits, not a hand-rolled fixture.
func realClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	c, s := net.Pipe()
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := s.Read(buf)
		got <- buf[:n]
		s.Close()
	}()
	tc := tls.Client(c, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	_ = tc.Handshake() // will fail (pipe closes) after the ClientHello is sent
	c.Close()
	return <-got
}

func TestParseClientHelloSNI(t *testing.T) {
	hello := realClientHello(t, "bank.example.com")
	got, ok := ParseClientHelloSNI(hello)
	if !ok {
		t.Fatal("failed to parse SNI from a real ClientHello")
	}
	if got != "bank.example.com" {
		t.Fatalf("SNI = %q, want bank.example.com", got)
	}
}

func TestParseClientHelloSNIRejects(t *testing.T) {
	cases := map[string][]byte{
		"empty":           {},
		"not handshake":   {23, 3, 3, 0, 1, 0},
		"truncated body":  {22, 3, 1, 0, 100, 1, 0, 0, 90},
		"not clienthello": {22, 3, 1, 0, 4, 2, 0, 0, 0},
	}
	for name, b := range cases {
		if _, ok := ParseClientHelloSNI(b); ok {
			t.Errorf("%s: expected rejection, got ok", name)
		}
	}
}
