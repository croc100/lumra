package live

import "encoding/binary"

// ParseServerHelloVersion extracts the negotiated TLS version from a ServerHello
// record. TLS 1.3 pins the record's legacy_version to 1.2 and carries the real
// version in a supported_versions extension, so both are checked; the extension
// wins when present. Returns ok=false for non-ServerHello or malformed input.
// Pure and bounds-checked against attacker-controlled wire data.
func ParseServerHelloVersion(rec []byte) (uint16, bool) {
	if len(rec) < 5 || rec[0] != 22 {
		return 0, false
	}
	return parseServerHelloMsg(rec[5:])
}

// parseServerHelloMsg reads the version from a bare ServerHello handshake message
// (type 2 + 3-byte length + body), as produced by the reassembler.
func parseServerHelloMsg(msg []byte) (uint16, bool) {
	if len(msg) < 4 || msg[0] != 2 { // handshake type 2 = ServerHello
		return 0, false
	}
	hlen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	body := msg[4:]
	if len(body) < hlen {
		return 0, false
	}
	body = body[:hlen]

	// ServerHello: legacy_version(2) + random(32).
	if len(body) < 34 {
		return 0, false
	}
	legacy := binary.BigEndian.Uint16(body[:2])
	p := body[34:]
	// session_id: len(1) + id.
	sid, ok := skipVec8(p)
	if !ok {
		return legacy, true // no extensions to refine with; report legacy
	}
	p = sid
	// cipher_suite(2) + compression_method(1).
	if len(p) < 3 {
		return legacy, true
	}
	p = p[3:]
	// extensions: len(2) + extensions.
	if len(p) < 2 {
		return legacy, true
	}
	extTotal := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if len(p) < extTotal {
		return legacy, true
	}
	p = p[:extTotal]
	if v, ok := supportedVersion(p); ok {
		return v, true
	}
	return legacy, true
}

// supportedVersion returns the server's chosen version from a supported_versions
// extension (type 0x002b), which in a ServerHello carries a single 2-byte value.
func supportedVersion(p []byte) (uint16, bool) {
	for len(p) >= 4 {
		extType := binary.BigEndian.Uint16(p)
		extLen := int(binary.BigEndian.Uint16(p[2:]))
		p = p[4:]
		if len(p) < extLen {
			return 0, false
		}
		if extType == 0x002b && extLen >= 2 {
			return binary.BigEndian.Uint16(p[:2]), true
		}
		p = p[extLen:]
	}
	return 0, false
}
