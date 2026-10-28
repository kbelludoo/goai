//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runLauncher re-execs this test binary as the launcher would be invoked and
// returns its exit code, so argument handling is tested without a real cgroup.
func runLauncher(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "GOAI_LAUNCHER_CHILD=1")
	out, err := cmd.CombinedOutput()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("cannot run helper: %v", err)
	}
	return string(out), code
}

func TestLauncherChild(t *testing.T) {
	if os.Getenv("GOAI_LAUNCHER_CHILD") != "1" {
		t.Skip("helper process")
	}
	main()
}

func TestUsageOnlyWhenPositionalArgumentsAreMissing(t *testing.T) {
	// Zero and one argument: usage error, exit 126.
	for _, args := range [][]string{{}, {"only-one"}} {
		out, code := runLauncher(t, args...)
		if code != 126 || !strings.Contains(out, "usage: goai-cgroup-exec") {
			t.Fatalf("args %v: code=%d out=%q", args, code, out)
		}
	}
}

func TestTargetWithoutExtraArgsIsNotAUsageError(t *testing.T) {
	// Two arguments must reach validation. The fake directory is refused with
	// the launch-denied code (126), never with the usage message.
	fake := filepath.Join(t.TempDir(), "not-a-cgroup")
	if err := os.Mkdir(fake, 0700); err != nil {
		t.Fatal(err)
	}
	out, code := runLauncher(t, fake, "/bin/true")
	if strings.Contains(out, "usage: goai-cgroup-exec") {
		t.Fatalf("well-formed command reported as a usage error: %q", out)
	}
	if code != 126 || !strings.Contains(out, "GOAI-CGROUP-020") {
		t.Fatalf("expected a fail-closed denial, got code=%d out=%q", code, out)
	}
}
