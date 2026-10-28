//go:build linux

package sandboxcheck

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestProcessCanaryArgsAreLockedDown(t *testing.T) {
	args := processCanaryArgs("/trusted/probe", "/host/private/scratch", strings.Repeat("a", 64))
	for _, flag := range []string{"--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "--clearenv", "--proc", "--tmpfs"} {
		if !slices.Contains(args, flag) {
			t.Fatalf("missing %s", flag)
		}
	}
	if slices.Contains(args, "--share-net") || slices.Contains(args, "--bind-try") {
		t.Fatal("unsafe opt-out")
	}
	binds := 0
	for i, arg := range args {
		if arg == "--bind" {
			binds++
			if i+2 >= len(args) || args[i+1] != "/host/private/scratch" || args[i+2] != "/goai/control" {
				t.Fatalf("unexpected bind mount: %v", args)
			}
		}
	}
	if binds != 1 {
		t.Fatalf("want exactly one private control bind, got %d", binds)
	}
}

func TestCanaryProcessScannerRequiresExactMarkerAndNamespace(t *testing.T) {
	root := t.TempDir()
	marker := strings.Repeat("a", 64)
	makeProc := func(pid, cmd, ns string) {
		t.Helper()
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(filepath.Join(dir, "ns"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmd), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(ns, filepath.Join(dir, "ns", "pid")); err != nil {
			t.Fatal(err)
		}
	}
	makeProc("1001", "/goai/probe\x00--canary-daemon\x00--canary-id\x00"+marker+"\x00", "pid:[555]")
	makeProc("1002", "/goai/probe\x00--process-audit\x00--canary-id\x00"+marker+"\x00", "pid:[555]")
	makeProc("1003", "/goai/probe\x00--canary-daemon\x00--canary-id\x00"+strings.Repeat("b", 64)+"\x00", "pid:[555]")
	matches, err := findCanaryDaemons(root, marker)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].hostPID != 1001 || matches[0].pidNamespace != "pid:[555]" {
		t.Fatalf("scanned wrong processes: %+v", matches)
	}
	if _, err := findCanaryDaemons(root, "wrong"); err == nil {
		t.Fatal("accepted malformed marker")
	}
}

// This positive control executes only the trusted probe on the test host, NOT
// agent code. The test proves the scanner sees a real running Setsid child.
func TestRealProcScannerDetectsTrustedDaemon(t *testing.T) {
	if testing.Short() {
		t.Skip("needs Go compiler")
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	marker := hex.EncodeToString(nonce[:])
	dir := t.TempDir()
	binary := filepath.Join(dir, "probe")
	build := exec.Command("go", "build", "-o", binary, "./cmd/goai-isolation-probe")
	build.Dir = filepath.Join("..", "..")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build trusted probe: %v %s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.Command(binary, "--canary-daemon", "--canary-id", marker, "--control", dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if err := waitForMarker(ctx, filepath.Join(dir, "ready"), marker); err != nil {
		t.Fatal(err)
	}
	matches, err := findCanaryDaemons("/proc", marker)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].hostPID != cmd.Process.Pid {
		t.Fatalf("could not see live trusted daemon: %+v pid=%d", matches, cmd.Process.Pid)
	}
	ownNS, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		t.Fatal(err)
	}
	if matches[0].pidNamespace != ownNS {
		t.Fatal("host positive control unexpectedly has different namespace")
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if still, err := findCanaryDaemons("/proc", marker); err != nil || len(still) != 0 {
		t.Fatalf("cannot verify exit: %+v %v", still, err)
	}
}

func TestProcessCanaryAuditFailClosedWithoutBwrap(t *testing.T) {
	host, err := readHostNamespaces()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
	defer cancel()
	err = auditDaemon(ctx, "/path/not/a/real/bwrap", "/path/not/a/real/probe", host)
	if err == nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing isolation backend was not rejected: %v", err)
	}
}
