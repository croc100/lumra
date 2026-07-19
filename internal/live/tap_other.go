//go:build !linux && !darwin && !windows

package live

import (
	"context"
	"fmt"
	"runtime"
)

type unsupportedTap struct{}

func newTap() Source { return unsupportedTap{} }

func (unsupportedTap) Run(context.Context, func(Event)) error {
	return fmt.Errorf("passive tap is not implemented for %s; feed packets via TunSource instead", runtime.GOOS)
}
