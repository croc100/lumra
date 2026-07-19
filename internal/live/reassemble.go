package live

import (
	"crypto/x509"
	"encoding/binary"
	"errors"
)

// The passive tap sees only whatever crosses the wire, and a TLS Certificate
// message routinely spans several TCP segments and several TLS records. To read
// the server's certificate without opening a connection of our own, we reassemble
// the server→client handshake stream: TLS records (type 22) are concatenated into
// a handshake byte stream, which is then split back into complete handshake
// messages. This works for TLS 1.2, where the Certificate travels in the clear;
// in TLS 1.3 it is encrypted (record type 23), so the reassembler simply stops —
// an absence that is itself honest (nothing to inspect, nothing asserted).

// maxHandshakeBuffer caps per-flow buffering so malformed or hostile length
// fields can never make the tap accumulate unbounded memory. A real certificate
// flight is a few KB; 64 KB is generous headroom.
const maxHandshakeBuffer = 64 << 10

// hsReassembler reassembles one flow's server→client handshake messages.
type hsReassembler struct {
	recBuf []byte // pending record-layer bytes not yet split into records
	hsBuf  []byte // concatenated handshake fragments not yet split into messages
	done   bool   // a non-handshake record (or overflow) was seen; stop buffering
}

// Feed appends server→client TCP payload and returns any handshake messages that
// became complete, each as its full bytes including the 4-byte message header.
func (r *hsReassembler) Feed(payload []byte) [][]byte {
	if r.done || len(payload) == 0 {
		return nil
	}
	r.recBuf = append(r.recBuf, payload...)
	if len(r.recBuf) > maxHandshakeBuffer {
		r.done = true
		return nil
	}
	// Split out complete TLS records; only handshake records feed the hsBuf.
	for len(r.recBuf) >= 5 {
		recType := r.recBuf[0]
		recLen := int(binary.BigEndian.Uint16(r.recBuf[3:5]))
		if recLen == 0 || len(r.recBuf) < 5+recLen {
			break // wait for the rest of this record
		}
		frag := r.recBuf[5 : 5+recLen]
		r.recBuf = r.recBuf[5+recLen:]
		if recType != 22 { // ChangeCipherSpec / application_data → handshake is done or encrypted
			r.done = true
			return r.drain()
		}
		r.hsBuf = append(r.hsBuf, frag...)
		if len(r.hsBuf) > maxHandshakeBuffer {
			r.done = true
			break
		}
	}
	return r.drain()
}

// drain splits the handshake buffer into complete messages.
func (r *hsReassembler) drain() [][]byte {
	var out [][]byte
	for len(r.hsBuf) >= 4 {
		msgLen := int(r.hsBuf[1])<<16 | int(r.hsBuf[2])<<8 | int(r.hsBuf[3])
		if len(r.hsBuf) < 4+msgLen {
			break // wait for the rest of this message
		}
		msg := r.hsBuf[:4+msgLen]
		r.hsBuf = r.hsBuf[4+msgLen:]
		out = append(out, msg)
	}
	return out
}

// extractCertificates reads the DER certificates from a TLS 1.2 Certificate
// handshake message (type 11). The leaf is first. Bounds-checked throughout.
func extractCertificates(msg []byte) ([][]byte, bool) {
	if len(msg) < 4 || msg[0] != 11 {
		return nil, false
	}
	p := msg[4:]
	if len(p) < 3 {
		return nil, false
	}
	total := u24(p)
	p = p[3:]
	if len(p) < total {
		return nil, false
	}
	p = p[:total]
	var out [][]byte
	for len(p) >= 3 {
		clen := u24(p)
		p = p[3:]
		if len(p) < clen {
			return nil, false
		}
		out = append(out, p[:clen])
		p = p[clen:]
	}
	return out, len(out) > 0
}

// u24 reads a big-endian 24-bit length.
func u24(b []byte) int { return int(b[0])<<16 | int(b[1])<<8 | int(b[2]) }

// inspectChain verifies a presented certificate chain against the system roots
// for sni. It returns the leaf subject and, crucially, whether the chain fails to
// reach a trusted authority — the signature of a substituted certificate, i.e. a
// man-in-the-middle reading the session. Expired or wrong-host certs are ordinary
// and are NOT reported as interception (mirrors the active TLS probe's rule).
func inspectChain(ders [][]byte, sni string) (leafSubject string, untrusted bool, ok bool) {
	if len(ders) == 0 {
		return "", false, false
	}
	leaf, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return "", false, false
	}
	inter := x509.NewCertPool()
	for _, d := range ders[1:] {
		if c, e := x509.ParseCertificate(d); e == nil {
			inter.AddCert(c)
		}
	}
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: sni, Intermediates: inter})
	var ua x509.UnknownAuthorityError
	return leaf.Subject.CommonName, errors.As(verr, &ua), true
}
