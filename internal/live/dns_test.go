package live

import "testing"

// dnsReply builds a minimal DNS response for name with the given A-record IPs.
func dnsReply(name string, ips ...[4]byte) []byte {
	msg := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, byte(len(ips) >> 8), byte(len(ips)), 0, 0, 0, 0}
	q := encodeName(name)
	msg = append(msg, q...)
	msg = append(msg, 0, 1, 0, 1) // QTYPE=A, QCLASS=IN
	for _, ip := range ips {
		msg = append(msg, 0xc0, 0x0c)  // name pointer to offset 12 (the question)
		msg = append(msg, 0, 1, 0, 1)  // TYPE=A, CLASS=IN
		msg = append(msg, 0, 0, 0, 60) // TTL
		msg = append(msg, 0, 4)        // RDLENGTH
		msg = append(msg, ip[:]...)
	}
	return msg
}

func encodeName(name string) []byte {
	var out []byte
	for len(name) > 0 {
		dot := len(name)
		for i := 0; i < len(name); i++ {
			if name[i] == '.' {
				dot = i
				break
			}
		}
		out = append(out, byte(dot))
		out = append(out, name[:dot]...)
		if dot == len(name) {
			break
		}
		name = name[dot+1:]
	}
	return append(out, 0)
}

func TestParseDNSReply(t *testing.T) {
	msg := dnsReply("blocked.example.com", [4]byte{0, 0, 0, 0}, [4]byte{93, 184, 216, 34})
	name, ips, ok := parseDNSReply(msg)
	if !ok {
		t.Fatal("parse failed")
	}
	if name != "blocked.example.com" {
		t.Errorf("name = %q", name)
	}
	if len(ips) != 2 || ips[0] != "0.0.0.0" || ips[1] != "93.184.216.34" {
		t.Errorf("ips = %v", ips)
	}
}

func TestParseDNSReplyRejectsQuery(t *testing.T) {
	// QR bit clear (a query, not a reply) → rejected.
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	q = append(q, encodeName("x.com")...)
	q = append(q, 0, 1, 0, 1)
	if _, _, ok := parseDNSReply(q); ok {
		t.Error("a DNS query should be rejected")
	}
}

func TestSuspiciousAnswer(t *testing.T) {
	cases := []struct {
		ips  []string
		want bool
	}{
		{[]string{"93.184.216.34"}, false},
		{[]string{"0.0.0.0"}, true},
		{[]string{"127.0.0.1"}, true},
		{[]string{"10.0.0.1"}, true},
		{[]string{"192.168.1.1"}, true},
		{[]string{"169.254.1.1"}, true},
		{[]string{"203.0.113.5"}, true},         // TEST-NET-3
		{[]string{"1.1.1.1", "10.0.0.1"}, true}, // any bad answer flags
		{nil, false},
	}
	for _, c := range cases {
		if _, got := suspiciousAnswer(c.ips); got != c.want {
			t.Errorf("suspiciousAnswer(%v) = %v, want %v", c.ips, got, c.want)
		}
	}
}
