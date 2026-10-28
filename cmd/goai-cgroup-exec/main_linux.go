//go:build linux

// goai-cgroup-exec is a trusted internal launcher, not an agent-facing tool.
// It migrates itself to an already-limited cgroup before execve of its target.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/kbelludoo/goai/internal/cgroupv2"
)

func main() {
	// Two positional arguments are the minimum: the cgroup and the absolute
	// target. Requiring a third made `goai-cgroup-exec /cgroup /bin/true` fail
	// with a usage error even though the command is well formed.
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: goai-cgroup-exec <prepared-cgroup> <absolute-target> [args...]")
		os.Exit(126)
	}
	target := os.Args[2]
	err := cgroupv2.ExecPrepared(os.Args[1], target, os.Args[2:])
	// Fail-closed: no target has started if validation or migration failed.
	fmt.Fprintln(os.Stderr, "goai-cgroup-exec:", err)
	if errors.Is(err, cgroupv2.ErrLaunchDenied) || errors.Is(err, cgroupv2.ErrJoinFailed) {
		os.Exit(126)
	}
	os.Exit(127)
}
