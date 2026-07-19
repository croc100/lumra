package live

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"
)

func TestRenderBoard(t *testing.T) {
	now := time.Unix(0, 0)
	flows := []Flow{
		{Domain: "github.com", Version: tls.VersionTLS13, Handshake: true, LastSeen: now},
		{Domain: "blocked.example", Resets: 2, LastSeen: now},
	}
	out := RenderBoard(flows, now)
	if !strings.Contains(out, "✅") || !strings.Contains(out, "github.com") || !strings.Contains(out, "TLS1.3") {
		t.Errorf("clean row missing:\n%s", out)
	}
	if !strings.Contains(out, "🚫") || !strings.Contains(out, "BLOCKED") {
		t.Errorf("blocked row missing:\n%s", out)
	}
}

func TestRenderBoardEmpty(t *testing.T) {
	if !strings.Contains(RenderBoard(nil, time.Unix(0, 0)), "waiting for traffic") {
		t.Error("empty board should show a waiting message")
	}
}
