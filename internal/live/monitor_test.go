package live

import (
	"testing"
)

func TestMonitorHandlePacketAndRows(t *testing.T) {
	m := NewMonitor()
	client := [4]byte{10, 0, 0, 2}
	server := [4]byte{93, 184, 216, 34}
	hello := realClientHello(t, "phone.example.com")
	m.HandlePacket(ipv4(protoTCP, client, server, tcpSeg(41000, 443, 0x18, hello)))

	rows := Rows(m.Snapshot())
	if len(rows) != 1 || rows[0].Domain != "phone.example.com" {
		t.Fatalf("expected one row for phone.example.com, got %+v", rows)
	}
	if rows[0].Badge == "" || rows[0].Nature == "" {
		t.Errorf("row missing badge/nature: %+v", rows[0])
	}
}

func TestMonitorRenderEmpty(t *testing.T) {
	if r := NewMonitor().Render(); r == "" {
		t.Fatal("Render should return the empty-board text")
	}
}
