package live

import "net"

// egressInterface returns the name and IPv4 address of the interface the host
// uses to reach the internet, so a capture backend binds to the link that
// actually carries traffic rather than guessing. It dials a UDP socket (no
// packets are sent) to learn the kernel's chosen source address, then matches
// that address to an interface.
func egressInterface() (name string, ip net.IP) {
	c, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return "", nil
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok || ua.IP.To4() == nil {
		return "", nil
	}
	ip = ua.IP.To4()

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", ip
	}
	for _, ifi := range ifaces {
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(ip) {
				return ifi.Name, ip
			}
		}
	}
	return "", ip
}
