//go:build linux

package live

import (
	"context"
	"syscall"
	"time"
)

// linuxTap sniffs the wire with an AF_PACKET socket and feeds each frame's IP
// packet to the shared dispatcher, which reads the TLS handshake metadata and
// DNS answers. It never decrypts; it reads only cleartext handshake/DNS bytes.
// Requires CAP_NET_RAW (root).
type linuxTap struct{}

func newTap() Source { return linuxTap{} }

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

	disp := newDispatcher(emit)
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
		ip, ok := parseEthernet(buf[:n])
		if !ok {
			continue
		}
		disp.handle(ip, time.Now())
	}
}

// htons converts a uint16 to network byte order for the AF_PACKET protocol field.
func htons(v uint16) uint16 { return v<<8 | v>>8 }
