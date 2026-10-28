//go:build !linux

package supervisor

import (
	"context"
	"errors"
	"time"
)

type Result struct {
	Output          string
	OutputTruncated bool
}
type Limits struct {
	MaxOutputBytes int
	PipeWaitDelay  time.Duration
}

// RunTrusted fails closed on systems where the Linux group supervisor is absent.
// It does not provide a security sandbox on Linux either.
func RunTrusted(_ context.Context, _ string, _ []string, _ string, _ Limits) (Result, error) {
	return Result{}, errors.New("process supervisor implemented for Linux only")
}
