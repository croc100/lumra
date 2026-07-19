package mobile

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

// dnsSinkholeReply builds a UDP/IPv4 packet: a DNS reply for name pointing to
// 0.0.0.0 (a sinkhole), delivered from a resolver — the mobile provider would
// hand exactly these bytes (raw IP, no framing) to Feed.
func dnsSinkholeReply(name string) []byte {
	// DNS message: reply, 1 question, 1 answer (A 0.0.0.0).
	msg := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)                       // root
	msg = append(msg, 0, 1, 0, 1)              // QTYPE A, QCLASS IN
	msg = append(msg, 0xc0, 0x0c)              // answer name pointer
	msg = append(msg, 0, 1, 0, 1, 0, 0, 0, 60) // A, IN, TTL
	msg = append(msg, 0, 4, 0, 0, 0, 0)        // RDLEN 4, 0.0.0.0

	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 53)
	binary.BigEndian.PutUint16(udp[2:4], 40000)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(msg)))
	udp = append(udp, msg...)

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(udp)))
	ip[8] = 64
	ip[9] = 17 // UDP
	copy(ip[12:16], []byte{1, 1, 1, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})
	return append(ip, udp...)
}

func TestCockpitFeedAndBoard(t *testing.T) {
	c := NewCockpit()
	if c.Count() != 0 {
		t.Fatal("new cockpit should be empty")
	}
	c.Feed(dnsSinkholeReply("blocked.example.com"))

	if c.Count() != 1 {
		t.Fatalf("expected 1 domain after feed, got %d", c.Count())
	}
	if !strings.Contains(c.Board(), "blocked.example.com") {
		t.Errorf("board should list the domain:\n%s", c.Board())
	}

	var rows []map[string]any
	if err := json.Unmarshal(c.BoardJSON(), &rows); err != nil {
		t.Fatalf("BoardJSON not valid JSON: %v", err)
	}
	if len(rows) != 1 || rows[0]["domain"] != "blocked.example.com" {
		t.Fatalf("unexpected BoardJSON: %s", c.BoardJSON())
	}
	if rows[0]["nature"] != "control" {
		t.Errorf("DNS sinkhole should read nature=control, got %v", rows[0]["nature"])
	}
}

func TestCockpitIgnoresGarbage(t *testing.T) {
	c := NewCockpit()
	c.Feed([]byte{0x00, 0x01, 0x02}) // too short to be IPv4 — must not panic
	if c.Count() != 0 {
		t.Fatal("garbage packet should not create a flow")
	}
}
