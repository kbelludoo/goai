//go:build linux

// The launcher takes no cgroup or executable path by argument: both are policy
// outcomes carried in a request from the supervisor. These tests exercise the
// real binary boundary (exit codes and stderr) without touching a cgroup.

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func runLauncher(t *testing.T, env []string, extraFiles []*os.File) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLauncherChild$")
	cmd.Env = append(append(os.Environ(), "GOAI_LAUNCHER_CHILD=1"), env...)
	cmd.ExtraFiles = extraFiles
	out, err := cmd.CombinedOutput()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("cannot run launcher: %v", err)
	}
	return string(out), code
}

func TestLauncherChild(t *testing.T) {
	if os.Getenv("GOAI_LAUNCHER_CHILD") != "1" {
		t.Skip("helper process")
	}
	main()
}

func TestMissingAuthorityRefusesBeforeAnythingRuns(t *testing.T) {
	out, code := runLauncher(t, nil, nil)
	if code != 126 || !strings.Contains(out, "GOAI-CGROUP-027") {
		t.Fatalf("missing policy: code=%d out=%q", code, out)
	}
}

func TestUntrustworthyAuthorityRefuses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authority.json")
	raw := []byte(`{"requester_uids":[0],"cgroup_roots":["/a"],"target_dirs":["/b"],"max_argv":4}`)
	if err := os.WriteFile(path, raw, 0666); err != nil {
		t.Fatal(err)
	}
	out, code := runLauncher(t, []string{"GOAI_AUTHORITY_CONFIG=" + path}, nil)
	if code != 126 || !strings.Contains(out, "GOAI-CGROUP-027") {
		t.Fatalf("group-writable policy accepted: code=%d out=%q", code, out)
	}
}

func TestNoSupervisorSocketRefuses(t *testing.T) {
	policyPath := writePolicy(t, uint32(os.Geteuid()))
	out, code := runLauncher(t, []string{"GOAI_AUTHORITY_CONFIG=" + policyPath}, nil, nil)
	if code == 0 || !strings.Contains(out, "supervisor socket") {
		t.Fatalf("launched without a supervisor channel: code=%d out=%q", code, out)
	}
}

func TestForeignRequesterIsRejected(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("socketpair unavailable: %v", err)
	}
	childEnd := os.NewFile(uintptr(fds[1]), "launcher")
	defer func() { syscall.Close(fds[0]); childEnd.Close() }()
	// Policy allows a different UID only, so this process must be refused.
	policyPath := writePolicy(t, uint32(os.Geteuid())+1)
	cmd := exec.Command(os.Args[0], "-test.run=^TestLauncherChild$")
	cmd.Env = append(os.Environ(), "GOAI_LAUNCHER_CHILD=1", "GOAI_AUTHORITY_CONFIG="+policyPath)
	cmd.ExtraFiles = []*os.File{childEnd}
	request, err := json.Marshal(map[string]any{
		"cgroup_path": "/sys/fs/cgroup/delegated/x",
		"target_path": "/bin/true",
		"argv":        []string{"/bin/true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := syscall.Write(fds[0], request); err != nil {
		t.Fatal(err)
	}
	waitErr := cmd.Wait()
	exitErr, ok := waitErr.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 125 {
		t.Fatalf("foreign requester not rejected with 125: %v", waitErr)
	}
}

func writePolicy(t *testing.T, uid uint32) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authority.json")
	policy := map[string]any{
		"requester_uids": []uint32{uid},
		"cgroup_roots":   []string{"/sys/fs/cgroup/delegated"},
		"target_dirs":    []string{"/bin", "/usr/bin"},
		"max_argv":       8,
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
