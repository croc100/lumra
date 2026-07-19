package live

import "context"

// Source is a producer of tap events. Passive desktop backends sniff the wire —
// Linux (AF_PACKET), macOS (BPF), Windows (SIO_RCVALL raw socket); TunSource
// consumes a tunnel's packets (desktop or mobile). Run blocks until ctx is
// cancelled or an unrecoverable error occurs, delivering each observation to emit.
type Source interface {
	Run(ctx context.Context, emit func(Event)) error
}

// NewTap returns the platform's passive tap. On unsupported platforms the
// returned Source's Run reports why no passive capture is available.
func NewTap() Source { return newTap() }

// errNeedPrivilege is the shared "not enough privilege" result every raw-capture
// backend returns, so the CLI can print one consistent message.
var errNeedPrivilege = &tapError{"passive tap needs elevated privilege (run with sudo / as admin)"}

type tapError struct{ msg string }

func (e *tapError) Error() string { return e.msg }
