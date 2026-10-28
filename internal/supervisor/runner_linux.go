//go:build linux

// Package supervisor runs trusted commands in a dedicated Linux process group.
// It does NOT provide a sandbox: it cannot isolate files, network, credentials,
// resources, or descendants that escape the group with setsid/setpgid.
package supervisor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Result contains bounded stdout/stderr captured from a trusted command.
// Truncation is indicated by OutputTruncated. It is NOT a validation receipt.
type Result struct {
	Output          string
	OutputTruncated bool
}

// Limits restrict in-memory diagnostics. They do NOT bound CPU, disk or memory
// consumption of the child and are not suitable for arbitrary agent code.
type Limits struct {
	MaxOutputBytes int
	PipeWaitDelay  time.Duration
}

const defaultOutputBytes = 256 * 1024
const defaultPipeWaitDelay = 250 * time.Millisecond

// boundedWriter discards bytes above max but continues draining the child pipe.
type boundedWriter struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(p)
	remaining := w.max - w.buf.Len()
	if remaining > 0 {
		use := n
		if use > remaining {
			use = remaining
		}
		_, _ = w.buf.Write(p[:use])
	}
	if n > remaining {
		w.truncated = true
	}
	return n, nil
}

// RunTrusted executes a **trusted** executable with fixed, internally controlled
// arguments. It sets a fresh process group and best-effort kills that group on
// cancellation AND ordinary exit to clean up cooperative descendants.
//
// Not a security boundary: a hostile descendant may call setsid/setpgid,
// and CommandContext cannot impose cgroups, mount/network namespaces, or an
// environment whitelist. Never use RunTrusted to execute untrusted Go tests.
func RunTrusted(ctx context.Context, executable string, args []string, dir string, limits Limits) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("nil context")
	}
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	if executable == "" {
		return Result{}, errors.New("missing trusted executable")
	}
	cap := limits.MaxOutputBytes
	if cap <= 0 {
		cap = defaultOutputBytes
	}
	delay := limits.PipeWaitDelay
	if delay <= 0 {
		delay = defaultPipeWaitDelay
	}
	writer := &boundedWriter{max: cap}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout, cmd.Stderr = writer, writer
	cmd.WaitDelay = delay
	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("start trusted command: %w", err)
	}
	pgid := cmd.Process.Pid // Setpgid=true creates a new group with this ID.
	// Canceling CommandContext kills the parent; additionally kill its group.
	// This monitor exits after Wait returns, and never touches unrelated groups
	// without a cancellation signal from this invocation.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		case <-done:
		}
	}()
	err := cmd.Wait()
	// Kill on success too: cmd.Wait can return with still-running descendants
	// (or with ErrWaitDelay if they hold inherited output pipes open).
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	close(done)
	writer.mu.Lock()
	result := Result{Output: writer.buf.String(), OutputTruncated: writer.truncated}
	writer.mu.Unlock()
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	return result, err
}
