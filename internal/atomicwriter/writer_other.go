//go:build !linux

// Package atomicwriter fails closed on unsupported platforms.
package atomicwriter

import "errors"

var (
	ErrConflict     = errors.New("GOAI-WRITE-001: source revision or identity changed")
	ErrLocked       = errors.New("GOAI-WRITE-002: another cooperative writer holds the lock")
	ErrUnsafeTarget = errors.New("GOAI-WRITE-003: target or lock is not a regular file")
	ErrInvalidPath  = errors.New("GOAI-WRITE-004: expected canonical absolute source path")
	ErrUnsupported  = errors.New("GOAI-WRITE-005: atomicwriter is unsupported on this platform")
)

func Replace(path, expectedSHA256 string, candidate []byte) error { return ErrUnsupported }
