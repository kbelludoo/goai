//go:build linux

package cgroupv2

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestAtRejectsUntrustedRoots(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "delegated")
	if err := os.Mkdir(real, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	for _, candidate := range []string{
		"",
		"relative/path",
		"/sys/fs/cgroup",           // the mount itself is not a delegation root
		"/tmp/does-not-exist-goai", // must already exist
		real,                       // exists, but outside the cgroup2 mount
		link,                       // symlink to a directory
		"/sys/fs/cgroup/../cgroup",
	} {
		if candidate == "" {
			if _, err := At(candidate); !errors.Is(err, ErrNotADirectory) {
				t.Errorf("accepted empty root: %v", err)
			}
			continue
		}
		if _, err := At(candidate); err == nil {
			t.Errorf("accepted untrusted delegation root %q", candidate)
		}
	}
}

func TestAtAcceptsOnlyRealCgroupDirectories(t *testing.T) {
	mountinfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Skip("no mountinfo")
	}
	_, mountpoint, err := cgroupMount(string(mountinfo))
	if err != nil {
		t.Skipf("no cgroup2 mount: %v", err)
	}
	// The current cgroup exists on the mount and is a directory. Whether it is
	// writable is host policy: At must fail with a delegation error, never with
	// ErrNotADirectory, when the only problem is permissions.
	//
	// Exception: when the process runs at the top of the hierarchy (common in
	// CI containers, where /proc/self/cgroup is "0::/"), the current cgroup IS
	// the mount root, which At rejects on purpose.
	cgroupText, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skip("no /proc/self/cgroup")
	}
	loc, err := Resolve(string(cgroupText), string(mountinfo))
	if err != nil {
		t.Skipf("cannot resolve current cgroup: %v", err)
	}
	if !strings.HasPrefix(loc.Parent(), mountpoint) {
		t.Fatalf("resolved outside mount: %q", loc.Parent())
	}
	if loc.Parent() == mountpoint {
		_, err := At(loc.Parent())
		if !errors.Is(err, ErrNotADirectory) {
			t.Fatalf("mount root must be refused as a delegation root, got %v", err)
		}
		t.Skip("process runs at the top of the cgroup hierarchy; nested delegation root unavailable")
	}
	_, err = At(loc.Parent())
	if err != nil && errors.Is(err, ErrNotADirectory) {
		t.Fatalf("real cgroup directory rejected as non-directory: %v", err)
	}
}

// EnableControllers and Prepare are exercised against synthetic directories.
// These are NOT kernel tests: they only prove that refusal paths work and that
// limit values are written and read back. A real placement test is opt-in below.
func syntheticRoot(t *testing.T, procs, controllers, subtree string) Root {
	t.Helper()
	root := t.TempDir()
	for name, content := range map[string]string{
		"cgroup.procs":           procs,
		"cgroup.controllers":     controllers,
		"cgroup.subtree_control": subtree,
		"cgroup.kill":            "",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return Root{mountpoint: root, path: root}
}

func TestEnableControllersRefusesBusyRoot(t *testing.T) {
	root := syntheticRoot(t, "1698\n", "cpu memory pids", "")
	if err := root.EnableControllers(); !errors.Is(err, ErrBusyRoot) {
		t.Fatalf("expected busy root refusal, got %v", err)
	}
	// Nothing may be enabled as a side effect of the refusal.
	got, err := os.ReadFile(filepath.Join(root.path, "cgroup.subtree_control"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "" {
		t.Fatalf("refusal modified subtree_control: %q", got)
	}
}

func TestEnableControllersRequiresAllControllers(t *testing.T) {
	root := syntheticRoot(t, "", "cpu memory", "")
	err := root.EnableControllers()
	if !errors.Is(err, ErrControllerUnavailable) || !strings.Contains(err.Error(), "pids") {
		t.Fatalf("expected missing pids controller, got %v", err)
	}
}

func TestPrepareRequiresDelegation(t *testing.T) {
	root := syntheticRoot(t, "", "cpu memory pids", "")
	if _, err := root.Prepare(defaultLimits()); !errors.Is(err, ErrNotDelegated) {
		t.Fatalf("expected delegation refusal, got %v", err)
	}
}

func TestPrepareRefusesUninitializedDirectory(t *testing.T) {
	// A delegated synthetic root whose child creation cannot produce cgroup
	// pseudo-files must fail, not write ordinary files into a normal directory.
	root := syntheticRoot(t, "", "cpu memory pids", "cpu memory pids")
	if _, err := root.Prepare(defaultLimits()); err == nil {
		t.Fatal("accepted a non-cgroup directory as an initialized cgroup2 child")
	}
}

func TestStartRefusesPreconfiguredPlacement(t *testing.T) {
	h := &Handle{path: t.TempDir()}
	dir, err := os.Open(h.path)
	if err != nil {
		t.Fatal(err)
	}
	h.dir = dir
	defer dir.Close()
	cmd := exec.Command("/bin/true")
	preconfigured := &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: 3}
	if err := h.Start(cmd, preconfigured); err == nil {
		t.Fatal("accepted a SysProcAttr that already sets cgroup placement")
	} else if !errors.Is(err, ErrInvalid) {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd.SysProcAttr != nil {
		t.Fatal("refusal must not mutate the command")
	}
}

func TestStartRefusesClosedHandleAndStartedCommand(t *testing.T) {
	h := &Handle{}
	if err := h.Start(exec.Command("/bin/true"), nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected invalid handle error, got %v", err)
	}
	started := exec.Command("/bin/true")
	if err := started.Start(); err != nil {
		t.Skipf("cannot start helper: %v", err)
	}
	_ = started.Wait()
	dir := t.TempDir()
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	open := &Handle{path: dir, dir: f}
	defer f.Close()
	if err := open.Start(started, nil); err == nil {
		t.Fatal("accepted an already started command")
	}
}

func TestRandomNameIsUniqueAndOpaque(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		name, err := randomName()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(name, "goai-") || len(name) != len("goai-")+32 {
			t.Fatalf("unexpected name %q", name)
		}
		if seen[name] {
			t.Fatalf("duplicate name %q", name)
		}
		seen[name] = true
	}
}

func TestContains(t *testing.T) {
	if !contains([]int{4, 5}, 5) || contains([]int{4, 5}, 6) || contains(nil, 1) {
		t.Fatal("contains is wrong")
	}
}

// TestRealAtomicPlacementAndLimits is the only test that proves kernel
// behaviour: clone3(CLONE_INTO_CGROUP) placement, limit enforcement files, and
// cgroup.kill. It requires an administrator-delegated, process-free root:
//
//	sudo systemd-run --scope --property=Delegate=yes ...   (or equivalent)
//	GOAI_TEST_CGROUP_ROOT=/sys/fs/cgroup/<delegated> go test ./internal/cgroupv2 -run Real -v
//
// Without the variable it skips, so CI never pretends the kernel was tested.
func TestRealAtomicPlacementAndLimits(t *testing.T) {
	rootPath := os.Getenv("GOAI_TEST_CGROUP_ROOT")
	if rootPath == "" {
		t.Skip("set GOAI_TEST_CGROUP_ROOT to a delegated, process-free cgroup v2 directory")
	}
	root, err := At(rootPath)
	if err != nil {
		t.Fatalf("delegation root rejected: %v", err)
	}
	if err := root.EnableControllers(); err != nil {
		t.Fatalf("EnableControllers: %v", err)
	}
	limits := Limits{MemoryMaxBytes: 128 << 20, CPUQuotaUS: 50000, CPUPeriodUS: 100000, PIDsMax: 32}
	h, err := root.Prepare(limits)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() {
		_ = h.Kill()
		_ = h.WaitEmpty(5 * time.Second)
		if err := h.Destroy(); err != nil {
			t.Errorf("Destroy after empty: %v", err)
		}
	}()

	// The child runs the test binary itself, so no fixture binary is needed.
	cmd := exec.Command(os.Args[0], "-test.run=TestCgroupChildProcess")
	cmd.Env = append(os.Environ(), "GOAI_CGROUP_CHILD=1")
	if err := h.Start(cmd, nil); err != nil {
		t.Fatalf("atomic placement failed: %v", err)
	}
	pids, err := h.Procs()
	if err != nil {
		t.Fatal(err)
	}
	if len(pids) != 1 || pids[0] != cmd.Process.Pid {
		t.Fatalf("unexpected membership %v for pid %d", pids, cmd.Process.Pid)
	}
	for name, want := range map[string]string{
		"memory.max": "134217728",
		"cpu.max":    "50000 100000",
		"pids.max":   "32",
	} {
		got, err := os.ReadFile(filepath.Join(h.Path(), name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if strings.TrimSpace(string(got)) != want {
			t.Fatalf("%s = %q, want %q", name, strings.TrimSpace(string(got)), want)
		}
	}
	if err := h.Kill(); err != nil {
		t.Fatalf("cgroup.kill: %v", err)
	}
	if err := h.WaitEmpty(5 * time.Second); err != nil {
		t.Fatalf("cgroup did not empty after kill: %v", err)
	}
	_ = cmd.Wait()
}

// TestCgroupChildProcess is the confined payload for the opt-in tests above and
// below. It never runs unless a parent test asked for a specific mode.
func TestCgroupChildProcess(t *testing.T) {
	mode := os.Getenv("GOAI_CGROUP_CHILD")
	if mode == "" {
		t.Skip("helper process for the opt-in cgroup tests")
	}
	// Brief delay so the parent can verify placement before pressure starts.
	time.Sleep(300 * time.Millisecond)
	switch mode {
	case "memory":
		// Touch every page: RSS grows until memory.max kills this process.
		buf := make([]byte, 512<<20)
		for i := 0; i < len(buf); i += 4096 {
			buf[i] = 1
		}
		// Reached only if the kernel did NOT enforce memory.max; the parent
		// bounds its wait and fails with that exact message.
		time.Sleep(30 * time.Second)
	case "cpu":
		deadline := time.Now().Add(1500 * time.Millisecond)
		x := 1
		for time.Now().Before(deadline) {
			x = x*3 + 1
		}
		_ = x
	default:
		time.Sleep(30 * time.Second)
	}
}

// counter reads a single "key value" line from a cgroup v2 stats file.
func counter(t *testing.T, path, key string) uint64 {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == key {
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				t.Fatalf("%s %s: %v", path, key, err)
			}
			return value
		}
	}
	t.Fatalf("%s has no %q counter", path, key)
	return 0
}

// startChild places one bounded payload in the cgroup through clone3 and waits
// for it, so a missing kill cannot hang the suite.
func startChild(t *testing.T, h *Handle, mode string, wait time.Duration) error {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestCgroupChildProcess")
	cmd.Env = append(os.Environ(), "GOAI_CGROUP_CHILD="+mode)
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := h.Start(cmd, nil); err != nil {
		t.Fatalf("%s payload was not placed atomically: %v", mode, err)
	}
	return waitBounded(t, cmd, wait)
}

func waitBounded(t *testing.T, cmd *exec.Cmd, wait time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(wait):
		_ = cmd.Process.Kill()
		<-done
		return fmt.Errorf("payload still running after %s: the kernel did not stop it", wait)
	}
}

// TestRealMemoryAndCPUContainment is the opt-in complement to
// TestRealAtomicPlacementAndLimits: placement and pids are covered there (and by
// the launcher probe), so this test proves the two limits that "configured" and
// "enforced" could otherwise be confused for each other.
//
//	GOAI_TEST_CGROUP_ROOT=/sys/fs/cgroup/<delegated> go test ./internal/cgroupv2 -run Real -v
func TestRealMemoryAndCPUContainment(t *testing.T) {
	rootPath := os.Getenv("GOAI_TEST_CGROUP_ROOT")
	if rootPath == "" {
		t.Skip("set GOAI_TEST_CGROUP_ROOT to a delegated, process-free cgroup v2 directory")
	}
	root, err := At(rootPath)
	if err != nil {
		t.Fatalf("delegation root rejected: %v", err)
	}
	if err := root.EnableControllers(); err != nil {
		t.Fatalf("EnableControllers: %v", err)
	}
	// 128 MiB is above the Go runtime's baseline and far below the payload's
	// 512 MiB touch loop, so an OOM kill is the only possible outcome.
	limits := Limits{MemoryMaxBytes: 128 << 20, CPUQuotaUS: 50000, CPUPeriodUS: 100000, PIDsMax: 16}
	h, err := root.Prepare(limits)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() {
		_ = h.Kill()
		_ = h.WaitEmpty(5 * time.Second)
		if err := h.Destroy(); err != nil {
			t.Errorf("Destroy after empty: %v", err)
		}
	}()

	oomBefore := counter(t, filepath.Join(h.Path(), "memory.events"), "oom_kill")
	if err := startChild(t, h, "memory", 25*time.Second); err == nil {
		t.Fatal("memory payload exited successfully under a 128 MiB cap; memory.max was not enforced")
	}
	oomAfter := counter(t, filepath.Join(h.Path(), "memory.events"), "oom_kill")
	if oomAfter <= oomBefore {
		t.Fatalf("memory.events oom_kill stayed %d: the kernel did not attribute an OOM kill to this cgroup", oomBefore)
	}
	if pids, err := h.Procs(); err != nil || len(pids) != 0 {
		t.Fatalf("cgroup not empty after OOM kill: %v %v", pids, err)
	}

	throttledBefore := counter(t, filepath.Join(h.Path(), "cpu.stat"), "nr_throttled")
	if err := startChild(t, h, "cpu", 20*time.Second); err != nil {
		t.Fatalf("cpu payload did not finish cleanly: %v", err)
	}
	throttledAfter := counter(t, filepath.Join(h.Path(), "cpu.stat"), "nr_throttled")
	if throttledAfter <= throttledBefore {
		t.Fatalf("cpu.stat nr_throttled stayed %d under a 50%% quota with a busy loop: cpu.max was not enforced", throttledBefore)
	}
}
