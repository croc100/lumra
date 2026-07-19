package live

import (
	"context"
	"errors"
	"io"
	"time"
)

// TunSource is the capture backend for a TUN / VPN tunnel: it reads raw IPv4
// packets and drives the same dispatcher as the desktop tap. This is the core
// the mobile clients reuse verbatim — an iOS NEPacketTunnelProvider or an Android
// VpnService hands each packet it receives to an io.Reader that this Source
// consumes, so the entire analysis (SNI, version, cert MITM, DNS redirect) runs
// unchanged on the phone. Like every backend it only observes: packets are read,
// never held, modified, or re-injected, so the tunnel stays monitor-only.
//
// A TUN device is packet-oriented — each Read yields exactly one IP packet.
// stripPrefix drops any per-packet framing header before the IP header (Linux
// tun PI header and macOS utun AF header are 4 bytes; a mobile provider that
// delivers raw IP uses 0).
type TunSource struct {
	r           io.Reader
	stripPrefix int
	mtu         int
}

// NewTunSource builds a TunSource reading packets from r, dropping stripPrefix
// framing bytes from the front of each packet.
func NewTunSource(r io.Reader, stripPrefix int) *TunSource {
	return &TunSource{r: r, stripPrefix: stripPrefix, mtu: 65536}
}

// Run reads packets until ctx is cancelled or the reader ends, dispatching each.
func (s *TunSource) Run(ctx context.Context, emit func(Event)) error {
	disp := newDispatcher(emit)
	buf := make([]byte, s.mtu)
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		n, err := s.r.Read(buf)
		if n > 0 {
			pkt := buf[:n]
			if len(pkt) > s.stripPrefix {
				disp.handle(pkt[s.stripPrefix:], time.Now())
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
}
