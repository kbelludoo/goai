//go:build linux

package cgroupv2

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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

// TestCgroupChildProcess is the confined payload for the opt-in test above.
func TestCgroupChildProcess(t *testing.T) {
	if os.Getenv("GOAI_CGROUP_CHILD") != "1" {
		t.Skip("helper process for TestRealAtomicPlacementAndLimits")
	}
	time.Sleep(30 * time.Second)
}
