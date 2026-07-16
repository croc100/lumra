//go:build linux

package probe

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// captureRST measures RST-injection attribution with a raw-socket probe.
//
// It crafts a bare TCP SYN to ip:443 from an ephemeral source port and listens,
// on a second raw socket, for the inbound reply. Two things are read from the
// IP header of what comes back: the TTL of the destination's own SYN/ACK (how
// far away the real server is) and the TTL of any RST (how far away whatever
// sent it is). A RST arriving materially closer than the server is an in-path
// injection — the attribution the rest of the pipeline folds in.
//
// Requires CAP_NET_RAW (root). Best-effort suppression of the kernel's own RST
// keeps the flow from being torn down before the reply is observed.
func captureRST(ctx context.Context, ip string) *RSTFinding {
	dst := net.ParseIP(ip).To4()
	if dst == nil {
		return &RSTFinding{Available: false, Note: "IPv4-only capture; target is not an IPv4 address"}
	}
	src := localSourceIP(dst)
	if src == nil {
		return &RSTFinding{Available: false, Note: "could not determine a source address to the target"}
	}

	send, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return unprivileged(err)
	}
	defer syscall.Close(send)

	recv, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return unprivileged(err)
	}
	defer syscall.Close(recv)
	// Short per-read timeout so the capture loop can honor the overall deadline.
	_ = syscall.SetsockoptTimeval(recv, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO,
		&syscall.Timeval{Sec: 1})

	sport := uint16(20000 + rand.Intn(40000))
	seq := rand.Uint32()

	// Keep the kernel from resetting a flow it has no socket for. Outbound-only,
	// so it never pollutes our inbound read; suppressing it just avoids tearing
	// the flow down early. Best-effort — the capture still works without it.
	suppressed, unsuppress := suppressKernelRST(sport)
	defer unsuppress()

	seg := buildTCPSegment(src, dst, sport, 443, seq, tcpSYN, 65535)
	var to [4]byte
	copy(to[:], dst)
	if err := syscall.Sendto(send, seg, 0, &syscall.SockaddrInet4{Addr: to}); err != nil {
		return &RSTFinding{Available: false, Note: "raw send failed: " + err.Error()}
	}

	f := &RSTFinding{Available: true}
	deadline := time.Now().Add(6 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}

	buf := make([]byte, 1500)
	var sawServer, sawRST bool
	for time.Now().Before(deadline) {
		n, _, rerr := syscall.Recvfrom(recv, buf, 0)
		if rerr != nil {
			continue // timeout (EAGAIN) or transient — retry until the deadline
		}
		p, ok := parseIPv4TCP(buf[:n])
		if !ok || !p.SrcIP.Equal(dst.To16()) || p.SrcPort != 443 || p.DstPort != sport {
			continue // not our flow
		}
		if p.has(tcpSYN) && p.has(tcpACK) && !sawServer {
			f.ServerTTL, sawServer = p.TTL, true
		}
		if p.has(tcpRST) && !sawRST {
			f.RSTTTL, sawRST = p.TTL, true
		}
		if sawServer && sawRST {
			break
		}
	}

	f.Injected = sawRST
	f.Note = describeCapture(sawServer, sawRST, suppressed, f.ServerTTL, f.RSTTTL)
	return f
}

// localSourceIP finds the address the kernel would use to reach dst, so the
// crafted segment's TCP checksum matches the packet the kernel actually sends.
func localSourceIP(dst net.IP) net.IP {
	c, err := net.Dial("udp", net.JoinHostPort(dst.String(), "443"))
	if err != nil {
		return nil
	}
	defer c.Close()
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return ua.IP.To4()
	}
	return nil
}

// unprivileged maps a socket-creation error to the honest "not measured" result.
func unprivileged(err error) *RSTFinding {
	if err == syscall.EPERM || err == syscall.EACCES {
		return &RSTFinding{Available: false, Note: "needs raw-socket privilege (run elevated / cap_net_raw)"}
	}
	return &RSTFinding{Available: false, Note: "raw socket unavailable: " + err.Error()}
}

// suppressKernelRST installs a temporary iptables rule dropping outbound RSTs
// for our source port, returning whether it took effect and a cleanup func.
func suppressKernelRST(sport uint16) (bool, func()) {
	sp := strconv.Itoa(int(sport))
	args := func(op string) []string {
		return []string{op, "OUTPUT", "-p", "tcp", "--sport", sp, "--tcp-flags", "RST", "RST", "-j", "DROP"}
	}
	if exec.Command("iptables", args("-I")...).Run() != nil {
		return false, func() {}
	}
	return true, func() { _ = exec.Command("iptables", args("-D")...).Run() }
}

func describeCapture(sawServer, sawRST, suppressed bool, serverTTL, rstTTL uint8) string {
	sup := ""
	if !suppressed {
		sup = " (kernel-RST suppression unavailable; flow may reset early)"
	}
	switch {
	case sawServer && sawRST:
		return fmt.Sprintf("server SYN/ACK TTL %d, RST TTL %d captured%s", serverTTL, rstTTL, sup)
	case sawRST:
		return fmt.Sprintf("RST TTL %d captured; no server SYN/ACK seen%s", rstTTL, sup)
	case sawServer:
		return fmt.Sprintf("server SYN/ACK TTL %d, no RST injected%s", serverTTL, sup)
	default:
		return "no matching reply captured to the crafted SYN" + sup
	}
}
