//go:build !linux

package live

import (
	"context"
	"fmt"
	"runtime"
)

type unsupportedTap struct{}

func newTap() Source { return unsupportedTap{} }

func (unsupportedTap) Run(context.Context, func(Event)) error {
	return fmt.Errorf("passive tap is implemented for Linux only (this host is %s)", runtime.GOOS)
}
