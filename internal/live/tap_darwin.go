//go:build darwin

package live

import (
	"context"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// darwinTap sniffs the wire on macOS through a BPF device (/dev/bpf*), the
// standard passive-capture path — no VPN, no kext. It binds to the egress
// interface, reads Ethernet frames, and feeds each frame's IP packet to the
// shared dispatcher. It never decrypts and never routes; it only observes.
// Requires root (BPF devices are root-owned).
type darwinTap struct{}

func newTap() Source { return darwinTap{} }

func (darwinTap) Run(ctx context.Context, emit func(Event)) error {
	ifName, _ := egressInterface()
	if ifName == "" {
		return fmt.Errorf("could not determine the active network interface to capture on")
	}

	fd, err := openBPF()
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	// Buffer length must be set before binding the interface.
	_ = bpfSetU32(fd, unix.BIOCSBLEN, 32<<10)
	if err := bpfSetIf(fd, ifName); err != nil {
		return fmt.Errorf("bind BPF to %s: %w", ifName, err)
	}
	// Immediate mode: deliver each packet as it arrives rather than buffering.
	_ = bpfSetU32(fd, unix.BIOCIMMEDIATE, 1)
	blen, err := bpfGetU32(fd, unix.BIOCGBLEN)
	if err != nil || blen <= 0 {
		blen = 32 << 10
	}

	disp := newDispatcher(emit)
	buf := make([]byte, blen)
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == unix.EINTR || err == unix.EAGAIN {
				continue
			}
			return err
		}
		dispatchBPF(disp, buf[:n])
	}
}

// openBPF opens the first free /dev/bpf device, mapping a permission error to the
// shared privilege message.
func openBPF() (int, error) {
	for i := 0; i < 256; i++ {
		fd, err := unix.Open(fmt.Sprintf("/dev/bpf%d", i), unix.O_RDONLY, 0)
		switch err {
		case nil:
			return fd, nil
		case unix.EBUSY:
			continue // in use by another process; try the next
		case unix.EACCES, unix.EPERM:
			return -1, errNeedPrivilege
		case unix.ENOENT:
			return -1, fmt.Errorf("no free BPF device available")
		}
	}
	return -1, fmt.Errorf("no free BPF device available")
}

// dispatchBPF walks the possibly-many bpf records in one read buffer, honouring
// each record's header length and BPF word alignment, and dispatches the frames.
func dispatchBPF(disp *dispatcher, b []byte) {
	now := time.Now()
	p := 0
	for p+int(unsafe.Sizeof(unix.BpfHdr{})) <= len(b) {
		hdr := (*unix.BpfHdr)(unsafe.Pointer(&b[p]))
		start := p + int(hdr.Hdrlen)
		end := start + int(hdr.Caplen)
		if start > len(b) || end > len(b) || start > end {
			return // malformed; stop this buffer
		}
		if ip, ok := parseEthernet(b[start:end]); ok {
			disp.handle(ip, now)
		}
		// Advance to the next record, word-aligned per BPF_WORDALIGN.
		p += bpfAlign(int(hdr.Hdrlen) + int(hdr.Caplen))
	}
}

// bpfAlign rounds up to the BPF alignment boundary (sizeof(int32) = 4 on darwin).
func bpfAlign(x int) int { return (x + 3) &^ 3 }

// The BPF ioctls that x/sys/unix does not wrap on darwin are issued directly. The
// u_int-valued ones (BIOCSBLEN/BIOCIMMEDIATE/BIOCGBLEN) take a pointer to a
// 32-bit value; BIOCSETIF takes a struct ifreq whose only field we set is the
// 16-byte interface name.

func bpfSetU32(fd int, req uint, v uint32) error {
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(unsafe.Pointer(&v)))
	if e != 0 {
		return e
	}
	return nil
}

func bpfGetU32(fd int, req uint) (int, error) {
	var v uint32
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(unsafe.Pointer(&v)))
	if e != 0 {
		return 0, e
	}
	return int(v), nil
}

func bpfSetIf(fd int, name string) error {
	var ifr [32]byte // sizeof(struct ifreq) on darwin
	copy(ifr[:16], name)
	_, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.BIOCSETIF), uintptr(unsafe.Pointer(&ifr[0])))
	if e != 0 {
		return e
	}
	return nil
}
