package probe

import (
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
)

func TestIsResetProvenance(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		// Kernel-attested resets — provenance-precise, always a reset.
		{"ECONNRESET", syscall.ECONNRESET, true},
		{"EPIPE", syscall.EPIPE, true},
		{"wrapped ECONNRESET", fmt.Errorf("read tcp: %w", syscall.ECONNRESET), true},
		{"net.ErrClosed", net.ErrClosed, true},
		{"OpError with ECONNRESET", &net.OpError{Op: "read", Err: syscall.ECONNRESET}, true},

		// Truncated stream mid-handshake — a teardown, kept.
		{"unexpected EOF", io.ErrUnexpectedEOF, true},

		// A clean close is NOT a reset — the key precision fix. A server-sent
		// alert / graceful EOF must not be read as interference.
		{"clean EOF", io.EOF, false},
		{"tls alert text", errors.New("remote error: tls: handshake failure"), false},
		{"generic dns error", errors.New("no such host"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isReset(tt.err); got != tt.want {
				t.Errorf("isReset(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
