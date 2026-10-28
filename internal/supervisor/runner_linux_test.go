//go:build linux

package supervisor

import (
	"context"
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

// Helper runs in a separate Go test subprocess. The supervisor deliberately
// uses only the Go test executable and arguments owned by the test suite.
func TestHelperProcess(t *testing.T) {
	switch os.Getenv("GOAI_SUPERVISOR_TEST_HELPER") {
	case "parent-hang", "parent-exit":
		f := os.Getenv("GOAI_SUPERVISOR_PIDFILE")
		child := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
		child.Env = append(os.Environ(), "GOAI_SUPERVISOR_TEST_HELPER=child")
		// Child inherits its process group from the trusted parent.
		if err := child.Start(); err != nil {
			os.Exit(17)
		}
		if err := os.WriteFile(f, []byte(strconv.Itoa(child.Process.Pid)), 0600); err != nil {
			os.Exit(18)
		}
		// Reap only on parent-hang; exit immediately on parent-exit, leaving
		// child alive and testing the supervisor cleanup-on-normal-exit path.
		if os.Getenv("GOAI_SUPERVISOR_TEST_HELPER") == "parent-exit" {
			os.Exit(0)
		}
		for {
			time.Sleep(time.Second)
		}
	case "child":
		for {
			time.Sleep(time.Second)
		}
	case "output":
		fmt.Print(strings.Repeat("x", 1024))
		os.Exit(0)
	}
}

func waitForPIDFile(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path)
		if err == nil {
			pid, err := strconv.Atoi(string(b))
			if err != nil {
				t.Fatal(err)
			}
			return pid
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("helper child did not start")
	return 0
}

func processRunning(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		return true
	}
	// /proc/PID/stat: the state is the first character after the final ') '.
	idx := strings.LastIndex(string(b), ") ")
	if idx < 0 || idx+2 >= len(b) {
		return true
	}
	state := b[idx+2]
	return state != 'Z' && state != 'X'
}

func eventuallyStopped(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !processRunning(pid) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Best effort cleanup of test processes if the assertion fails.
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Fatalf("child PID %d still running after supervisor returned", pid)
}

func TestCancellationKillsGroup(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns subprocesses")
	}
	dir := t.TempDir()
	pidfile := filepath.Join(dir, "child.pid")
	t.Setenv("GOAI_SUPERVISOR_TEST_HELPER", "parent-hang")
	t.Setenv("GOAI_SUPERVISOR_PIDFILE", pidfile)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := RunTrusted(ctx, os.Args[0], []string{"-test.run=^TestHelperProcess$"}, dir, Limits{})
		done <- err
	}()
	pid := waitForPIDFile(t, pidfile)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("supervisor did not return after cancellation")
	}
	eventuallyStopped(t, pid)
}

func TestNormalParentExitKillsRemainingGroup(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns subprocesses")
	}
	dir := t.TempDir()
	pidfile := filepath.Join(dir, "child.pid")
	t.Setenv("GOAI_SUPERVISOR_TEST_HELPER", "parent-exit")
	t.Setenv("GOAI_SUPERVISOR_PIDFILE", pidfile)
	_, err := RunTrusted(context.Background(), os.Args[0], []string{"-test.run=^TestHelperProcess$"}, dir, Limits{})
	if err != nil {
		t.Fatalf("normal trusted parent exited: %v", err)
	}
	pid := waitForPIDFile(t, pidfile)
	eventuallyStopped(t, pid)
}

func TestBoundedOutput(t *testing.T) {
	t.Setenv("GOAI_SUPERVISOR_TEST_HELPER", "output")
	res, err := RunTrusted(context.Background(), os.Args[0], []string{"-test.run=^TestHelperProcess$"}, t.TempDir(), Limits{MaxOutputBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Output) != 64 || !res.OutputTruncated {
		t.Fatalf("%d bytes, truncated=%t", len(res.Output), res.OutputTruncated)
	}
}

func TestCanceledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := RunTrusted(ctx, os.Args[0], nil, "", Limits{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
}
