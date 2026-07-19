//go:build linux

package live

import (
	"context"
	"encoding/binary"
	"syscall"
	"time"
)

// linuxTap sniffs the wire with an AF_PACKET socket and turns the cleartext TLS
// handshake metadata of port-443 flows into tap events. It never decrypts: it
// reads the SNI from ClientHellos, the negotiated version from ServerHellos, and
// notes RSTs. Requires CAP_NET_RAW (root).
type linuxTap struct{}

func newTap() Source { return linuxTap{} }

// flowKey identifies one connection by the server IP and the client's ephemeral
// port, which together are stable across both directions of the flow.
type flowKey struct {
	serverIP [4]byte
	clientPt uint16
}

func (linuxTap) Run(ctx context.Context, emit func(Event)) error {
	// ETH_P_ALL in network byte order captures every frame on every interface.
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		if err == syscall.EPERM || err == syscall.EACCES {
			return errNeedPrivilege
		}
		return err
	}
	defer syscall.Close(fd)
	// Short read timeout so ctx cancellation is honored promptly.
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 1})

	// Map each flow to the domain learned from its ClientHello, so inbound
	// ServerHellos and RSTs can be attributed back to a name.
	domains := make(map[flowKey]string)
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, _, rerr := syscall.Recvfrom(fd, buf, 0)
		if rerr != nil {
			continue // timeout or transient
		}
		fr, ok := parseFrame(buf[:n])
		if !ok {
			continue
		}
		now := time.Now()
		switch {
		case fr.dstPort == 443: // outbound to a server
			key := flowKey{fr.dstIP, fr.srcPort}
			if sni, ok := ParseClientHelloSNI(fr.payload); ok {
				domains[key] = sni
				emit(Event{Kind: ClientHello, Domain: sni, At: now})
			}
		case fr.srcPort == 443: // inbound from a server
			key := flowKey{fr.srcIP, fr.dstPort}
			dom := domains[key]
			if dom == "" {
				continue // no ClientHello seen for this flow; nothing to attribute
			}
			if fr.flags&flagRST != 0 {
				emit(Event{Kind: Reset, Domain: dom, At: now})
				delete(domains, key)
				continue
			}
			if v, ok := ParseServerHelloVersion(fr.payload); ok {
				emit(Event{Kind: ServerHello, Domain: dom, Version: v, At: now})
			}
		}
	}
}

const flagRST = 1 << 2

// frame is the parsed subset of an Ethernet/IPv4/TCP packet the tap needs.
type frame struct {
	srcIP, dstIP     [4]byte
	srcPort, dstPort uint16
	flags            byte
	payload          []byte // TCP payload (TLS records begin here)
}

// parseFrame decodes an Ethernet II frame carrying IPv4/TCP, returning ok=false
// for anything else. Bounds are checked at every step against raw wire data.
func parseFrame(b []byte) (frame, bool) {
	if len(b) < 14 || binary.BigEndian.Uint16(b[12:14]) != 0x0800 {
		return frame{}, false // not IPv4
	}
	ip := b[14:]
	if len(ip) < 20 || ip[0]>>4 != 4 || ip[9] != 6 { // IPv4 + TCP
		return frame{}, false
	}
	ihl := int(ip[0]&0x0f) * 4
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if ihl < 20 || len(ip) < ihl || totalLen < ihl || totalLen > len(ip) {
		return frame{}, false
	}
	tcp := ip[ihl:totalLen]
	if len(tcp) < 20 {
		return frame{}, false
	}
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || len(tcp) < dataOff {
		return frame{}, false
	}
	var f frame
	copy(f.srcIP[:], ip[12:16])
	copy(f.dstIP[:], ip[16:20])
	f.srcPort = binary.BigEndian.Uint16(tcp[0:2])
	f.dstPort = binary.BigEndian.Uint16(tcp[2:4])
	f.flags = tcp[13]
	f.payload = tcp[dataOff:]
	return f, true
}

// htons converts a uint16 to network byte order for the AF_PACKET protocol field.
func htons(v uint16) uint16 { return v<<8 | v>>8 }

var errNeedPrivilege = &tapError{"passive tap needs raw-socket privilege (run elevated / cap_net_raw)"}

type tapError struct{ msg string }

func (e *tapError) Error() string { return e.msg }
