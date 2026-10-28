//go:build linux

package cgroupv2

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// writeTestAuthority installs a policy owned by the current user, allowing the
// test binary directory and the delegated cgroup root.
func writeTestAuthority(t *testing.T, cgroupRoot, targetDir string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authority.json")
	policy := map[string]any{
		"requester_uids": []uint32{uint32(os.Geteuid())},
		"cgroup_roots":   []string{cgroupRoot},
		"target_dirs":    []string{targetDir},
		"max_argv":       16,
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

// socketpair returns the supervisor end and the child end of a unix socket.
func socketpair(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("socketpair unavailable: %v", err)
	}
	supervisor := os.NewFile(uintptr(fds[0]), "supervisor")
	child := os.NewFile(uintptr(fds[1]), "launcher")
	t.Cleanup(func() { supervisor.Close(); child.Close() })
	return supervisor, child
}

// runLauncherWithRequest starts the launcher, sends one request, and returns its
// combined output. The request is written after start so SO_PEERCRED identifies
// this test process.
func runLauncherWithRequest(t *testing.T, cmd *exec.Cmd, supervisor *os.File, request []byte) ([]byte, error) {
	t.Helper()
	conn, err := net.FileConn(supervisor)
	if err != nil {
		t.Fatal(err)
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		t.Fatal("supervisor end is not a unix socket")
	}
	defer unixConn.Close()
	if _, err := unixConn.Write(request); err != nil {
		t.Fatal(err)
	}
	unixConn.CloseWrite()
	return cmd.CombinedOutput()
}

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
	// The launcher takes no paths by argument: the test acts as the supervisor,
	// installs a policy, and sends the request over an inherited unix socket so
	// the kernel can report the requester's UID.
	authorityPath := writeTestAuthority(t, loc.Parent(), dir)
	supervisor, child := socketpair(t)
	request, err := json.Marshal(Request{CgroupPath: cg.Path(), TargetPath: probe, Argv: []string{probe, "probe", cg.Path()}})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, wrapper)
	cmd.Env = append(os.Environ(), "GOAI_AUTHORITY_CONFIG="+authorityPath)
	cmd.ExtraFiles = []*os.File{child}
	cmd.Stdin = strings.NewReader("")
	out, err := runLauncherWithRequest(t, cmd, supervisor, request)
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
