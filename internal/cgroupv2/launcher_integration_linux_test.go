//go:build linux

package cgroupv2

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Explicit opt-in ONLY on a dedicated Linux test host with delegated cgroup2.
// This is a bounded pressure probe, never an uncontrolled fork bomb. It proves
// cgroup pids denial for a trusted probe, NOT bwrap/mount/network isolation.
func TestCgroupContainmentRealOptIn(t *testing.T) {
	if os.Getenv("GOAI_CGROUP_INTEGRATION") != "1" {
		t.Skip("set GOAI_CGROUP_INTEGRATION=1 on dedicated delegated Linux host")
	}
	loc, err := Discover()
	if err != nil {
		t.Fatalf("opt-in requires cgroup2: %v", err)
	}
	if err := CheckDelegation(loc); err != nil {
		t.Fatalf("opt-in requires delegated cgroup2: %v", err)
	}

	cg, err := Prepare(loc, Limits{MemoryMaxBytes: 512 * 1024 * 1024, CPUQuotaUS: 50000, CPUPeriodUS: 100000, PIDsMax: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cg.Remove(); err != nil {
			// A unique test cgroup must never remain populated indefinitely.
			_ = os.WriteFile(filepath.Join(cg.Path(), "cgroup.kill"), []byte("1"), 0200)
			if err := cg.Remove(); err != nil {
				t.Errorf("cleanup cgroup: %v", err)
			}
		}
	}()
	dir := t.TempDir()
	wrapper := filepath.Join(dir, "goai-cgroup-exec")
	probe := filepath.Join(dir, "goai-cgroup-test-probe")
	for _, pair := range [][2]string{{wrapper, "../../cmd/goai-cgroup-exec"}, {probe, "./testdata/probe"}} {
		c := exec.Command("go", "build", "-o", pair[0], pair[1])
		c.Dir = "."
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v: %s", pair[1], err, out)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	// cgroup path is a direct child of the current cgroup. The launcher joins
	// itself before exec. The test probe verifies membership and denied forks.
	cmd := exec.CommandContext(ctx, wrapper, cg.Path(), probe, "probe", cg.Path())
	out, err := cmd.CombinedOutput()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatal("bounded cgroup integration timed out")
		}
		t.Fatalf("kernel containment probe failed: %v output=%s", err, out)
	}
	if !strings.Contains(string(out), "contained:") {
		t.Fatalf("unexpected probe result: %s", out)
	}
}
