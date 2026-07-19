package probe

import (
	"crypto/tls"
	"testing"

	"github.com/croc100/lumra/internal/verdict"
)

func TestClassifyDowngrade(t *testing.T) {
	cases := []struct {
		name   string
		def    versionAttempt
		forced versionAttempt
		want   bool
	}{
		{
			name:   "1.2 works, 1.3 reset → stripped",
			def:    versionAttempt{HandshakeOK: true, Negotiated: tls.VersionTLS12},
			forced: versionAttempt{Reset: true},
			want:   true,
		},
		{
			name:   "1.3 negotiates normally → no signal",
			def:    versionAttempt{HandshakeOK: true, Negotiated: tls.VersionTLS13},
			forced: versionAttempt{HandshakeOK: true, Negotiated: tls.VersionTLS13},
			want:   false,
		},
		{
			name:   "1.2 works, 1.3 refused by server alert (not reset) → no signal",
			def:    versionAttempt{HandshakeOK: true, Negotiated: tls.VersionTLS12},
			forced: versionAttempt{Err: "protocol version not supported"},
			want:   false,
		},
		{
			name:   "1.3 forced arm times out → not a reset, no signal",
			def:    versionAttempt{HandshakeOK: true, Negotiated: tls.VersionTLS12},
			forced: versionAttempt{Timeout: true},
			want:   false,
		},
		{
			name:   "default handshake failed → nothing to conclude",
			def:    versionAttempt{},
			forced: versionAttempt{Reset: true},
			want:   false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, got := classifyDowngrade(c.def, c.forced)
			if got != c.want {
				t.Fatalf("classifyDowngrade = %v, want %v", got, c.want)
			}
		})
	}
}

func TestDowngradeContributeSetsSurveillance(t *testing.T) {
	f := &DowngradeFinding{
		Domain:  "x",
		IP:      "1.2.3.4",
		Default: versionAttempt{HandshakeOK: true, Negotiated: tls.VersionTLS12},
		Forced:  versionAttempt{Reset: true},
	}
	v := &verdict.Verdict{Type: verdict.OK}
	f.Contribute(v)
	if v.Type != verdict.TLSDowngrade {
		t.Fatalf("Type = %s, want TLS_DOWNGRADE", v.Type)
	}
	if verdict.NatureOf(v.Type) != verdict.NatureSurveillance {
		t.Fatalf("nature = %s, want surveillance", verdict.NatureOf(v.Type))
	}
}
