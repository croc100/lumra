package live

import "testing"

// TestParseServerHelloVersionSynthetic builds a minimal ServerHello with a
// supported_versions extension announcing TLS 1.3 and confirms the extension
// wins over the legacy_version field (the TLS 1.3 wire behaviour).
func TestParseServerHelloVersionSynthetic(t *testing.T) {
	sh := buildServerHello(0x0303, []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04})
	v, ok := ParseServerHelloVersion(sh)
	if !ok {
		t.Fatal("failed to parse ServerHello")
	}
	if v != 0x0304 {
		t.Fatalf("version = 0x%04x, want 0x0304 (supported_versions wins)", v)
	}
}

func TestParseServerHelloVersionLegacy(t *testing.T) {
	sh := buildServerHello(0x0303, nil) // no extensions → legacy_version
	v, ok := ParseServerHelloVersion(sh)
	if !ok || v != 0x0303 {
		t.Fatalf("version = 0x%04x ok=%v, want 0x0303", v, ok)
	}
}

func TestParseServerHelloVersionRejects(t *testing.T) {
	cases := map[string][]byte{
		"empty":         {},
		"not handshake": {23, 3, 3, 0, 1, 0},
		"clienthello":   {22, 3, 3, 0, 4, 1, 0, 0, 0},
	}
	for name, b := range cases {
		if _, ok := ParseServerHelloVersion(b); ok {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

// buildServerHello assembles a wire-format ServerHello record with the given
// legacy version and raw extensions block (nil for none).
func buildServerHello(legacy uint16, exts []byte) []byte {
	hs := []byte{byte(legacy >> 8), byte(legacy)}
	hs = append(hs, make([]byte, 32)...) // random
	hs = append(hs, 0)                   // session_id len 0
	hs = append(hs, 0x13, 0x01)          // cipher_suite
	hs = append(hs, 0)                   // compression_method
	if exts != nil {
		hs = append(hs, byte(len(exts)>>8), byte(len(exts)))
		hs = append(hs, exts...)
	}
	// handshake header: type 2, 3-byte length.
	body := append([]byte{2, byte(len(hs) >> 16), byte(len(hs) >> 8), byte(len(hs))}, hs...)
	// record header: type 22, version, 2-byte length.
	rec := append([]byte{22, 3, 3, byte(len(body) >> 8), byte(len(body))}, body...)
	return rec
}
