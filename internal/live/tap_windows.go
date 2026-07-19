//go:build windows

package live

import (
	"context"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowsTap sniffs the wire on Windows through a raw IP socket placed in
// promiscuous mode with SIO_RCVALL — the built-in capture path, no npcap/WinPcap
// driver. The socket delivers whole IP packets (no link-layer header), which go
// straight to the shared dispatcher. It never decrypts and never routes; it only
// observes. Requires Administrator (raw sockets are privileged).
type windowsTap struct{}

func newTap() Source { return windowsTap{} }

// SIO_RCVALL enables receiving all IP packets through the bound interface.
const sioRcvall = windows.IOC_IN | windows.IOC_VENDOR | 1

func (windowsTap) Run(ctx context.Context, emit func(Event)) error {
	_, ip := egressInterface()
	if ip == nil {
		return fmt.Errorf("could not determine the active local IPv4 address to capture on")
	}

	fd, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_IP)
	if err != nil {
		if err == windows.WSAEACCES {
			return errNeedPrivilege
		}
		return err
	}
	defer windows.Closesocket(fd)

	var addr windows.SockaddrInet4
	copy(addr.Addr[:], ip.To4())
	if err := windows.Bind(fd, &addr); err != nil {
		return fmt.Errorf("bind raw socket to %s: %w", ip, err)
	}

	// Promiscuous receive of every IP packet on this interface.
	var in, out uint32 = 1, 0
	var ret uint32
	if err := windows.WSAIoctl(fd, sioRcvall,
		(*byte)(unsafe.Pointer(&in)), 4, (*byte)(unsafe.Pointer(&out)), 4,
		&ret, nil, 0); err != nil {
		if err == windows.WSAEACCES {
			return errNeedPrivilege
		}
		return fmt.Errorf("SIO_RCVALL: %w", err)
	}

	// A receive timeout lets ctx cancellation be honoured between reads.
	_ = windows.SetsockoptInt(fd, windows.SOL_SOCKET, windows.SO_RCVTIMEO, 1000)

	disp := newDispatcher(emit)
	buf := make([]byte, 65536)
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, _, err := windows.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == windows.WSAETIMEDOUT || err == windows.WSAEINTR {
				continue
			}
			return err
		}
		if n > 0 {
			disp.handle(buf[:n], time.Now())
		}
	}
}
