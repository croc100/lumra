package live

import "context"

// Source is a producer of tap events. The Linux implementation sniffs the wire;
// other platforms return an unsupported error. Run blocks until ctx is cancelled
// or an unrecoverable error occurs, delivering each observation to emit.
type Source interface {
	Run(ctx context.Context, emit func(Event)) error
}

// NewTap returns the platform's passive tap. On unsupported platforms the
// returned Source's Run reports why no passive capture is available.
func NewTap() Source { return newTap() }
