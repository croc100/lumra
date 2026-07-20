// Package live turns Lumra from a one-shot diagnostic into an always-on cockpit:
// a passive tap observes the TLS metadata of every connection the host makes and
// a Tracker keeps a live, per-domain board of what is happening — clean, blocked,
// or watched. Nothing is decrypted; only the cleartext handshake metadata (SNI,
// version, resets) is read, keeping Lumra a measurement tool, not an interceptor.
package live

import "encoding/binary"

// ParseClientHelloSNI extracts the server_name (SNI) from a TLS ClientHello
// carried in a TCP payload. rec is the TLS record as it appears on the wire,
// starting at the record header. It returns ok=false for anything that is not a
// ClientHello bearing an SNI extension. Pure and bounds-checked — the input is
// attacker-controlled wire data, so every field length is validated before use.
func ParseClientHelloSNI(rec []byte) (string, bool) {
	// TLS record header: type(1)=22 handshake, version(2), length(2).
	if len(rec) < 5 || rec[0] != 22 {
		return "", false
	}
	return clientHelloSNI(rec[5:])
}

// clientHelloSNI extracts the SNI from a complete ClientHello handshake message
// (starting at the 4-byte handshake header). It is the segment-independent core:
// the single-segment fast path calls it via ParseClientHelloSNI, and the client
// reassembler calls it on a message rebuilt from several TCP segments — modern
// ClientHellos routinely exceed one segment (GREASE, post-quantum key shares).
func clientHelloSNI(msg []byte) (string, bool) {
	// Handshake header: type(1)=1 ClientHello, length(3).
	if len(msg) < 4 || msg[0] != 1 {
		return "", false
	}
	hlen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	body := msg[4:]
	if len(body) < hlen {
		return "", false // truncated message
	}
	body = body[:hlen]

	// ClientHello: version(2) + random(32).
	if len(body) < 34 {
		return "", false
	}
	p := body[34:]
	// session_id: len(1) + id.
	sid, ok := skipVec8(p)
	if !ok {
		return "", false
	}
	p = sid
	// cipher_suites: len(2) + suites.
	cs, ok := skipVec16(p)
	if !ok {
		return "", false
	}
	p = cs
	// compression_methods: len(1) + methods.
	cm, ok := skipVec8(p)
	if !ok {
		return "", false
	}
	p = cm
	// extensions: len(2) + extensions.
	if len(p) < 2 {
		return "", false
	}
	extTotal := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if len(p) < extTotal {
		return "", false
	}
	p = p[:extTotal]
	return findSNIExtension(p)
}

// findSNIExtension walks the extensions block and returns the first host_name in
// a server_name extension (type 0x0000).
func findSNIExtension(p []byte) (string, bool) {
	for len(p) >= 4 {
		extType := binary.BigEndian.Uint16(p)
		extLen := int(binary.BigEndian.Uint16(p[2:]))
		p = p[4:]
		if len(p) < extLen {
			return "", false
		}
		if extType == 0 { // server_name
			return parseServerName(p[:extLen])
		}
		p = p[extLen:]
	}
	return "", false
}

// parseServerName reads a ServerNameList and returns the first host_name entry.
func parseServerName(p []byte) (string, bool) {
	// ServerNameList: list_len(2), then entries of name_type(1)+len(2)+name.
	if len(p) < 2 {
		return "", false
	}
	listLen := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if len(p) < listLen {
		return "", false
	}
	p = p[:listLen]
	for len(p) >= 3 {
		nameType := p[0]
		nameLen := int(binary.BigEndian.Uint16(p[1:]))
		p = p[3:]
		if len(p) < nameLen {
			return "", false
		}
		if nameType == 0 { // host_name
			return string(p[:nameLen]), true
		}
		p = p[nameLen:]
	}
	return "", false
}

// skipVec8 consumes a length-prefixed (1-byte) vector and returns the remainder.
func skipVec8(p []byte) ([]byte, bool) {
	if len(p) < 1 {
		return nil, false
	}
	n := int(p[0])
	if len(p) < 1+n {
		return nil, false
	}
	return p[1+n:], true
}

// skipVec16 consumes a length-prefixed (2-byte) vector and returns the remainder.
func skipVec16(p []byte) ([]byte, bool) {
	if len(p) < 2 {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(p))
	if len(p) < 2+n {
		return nil, false
	}
	return p[2+n:], true
}
