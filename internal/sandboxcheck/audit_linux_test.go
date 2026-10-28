//go:build linux

package sandboxcheck

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestBwrapArgsRestrictHostMounts(t *testing.T) {
	args := bwrapArgs("/trusted/helper", "http://127.0.0.1:8888/canary", "/tmp/goai-sentinel-xxxx/probe")
	for _, required := range []string{"--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "--tmpfs", "--clearenv", "--ro-bind", "--proc", "--dev"} {
		if !slices.Contains(args, required) {
			t.Fatalf("missing %q", required)
		}
	}
	if slices.Contains(args, "--share-net") || slices.Contains(args, "--bind") {
		t.Fatal("unexpected shared network or writable host bind")
	}
	for i, a := range args {
		if a == "--ro-bind" {
			if i+2 >= len(args) || args[i+1] != "/trusted/helper" || args[i+2] != "/goai/probe" {
				t.Fatal("host library/project mount unexpected")
			}
		}
	}
	joined := strings.Join(args, " ")
	for _, forbidden := range []string{"/home ", "/usr /usr", "/tmp /tmp"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("unexpected host directory bind: %s", joined)
		}
	}
}

func TestFailClosedWhenBackendMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	a, err := NewAuditor(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Audit(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing bwrap must fail closed: %v", err)
	}
	if !a.Quarantined() {
		t.Fatal("backend failure must quarantine auditor")
	}
	if _, err = a.Audit(context.Background()); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("quarantined auditor ran again: %v", err)
	}
}

// Opt-in real kernel test: bwrap and user namespace availability vary widely
// between machines/CI runners. The default suite never claims real isolation.
func TestBubblewrapRealIntegrationOptIn(t *testing.T) {
	if os.Getenv("GOAI_BWRAP_INTEGRATION") != "1" {
		t.Skip("set GOAI_BWRAP_INTEGRATION=1 to test actual Linux namespaces")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Fatalf("opted-in integration requires bwrap: %v", err)
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "goai-probe")
	cmd := exec.Command("go", "build", "-o", binary, "./cmd/goai-isolation-probe")
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build probe: %v: %s", err, output)
	}
	a, err := NewAuditor(binary)
	if err != nil {
		t.Fatal(err)
	}
	report, err := a.Audit(context.Background())
	if err != nil {
		t.Fatalf("isolation probe fail closed: %v", err)
	}
	if report.Backend != "bubblewrap" || report.Child.HostReachable || report.Child.SentinelReadable {
		t.Fatalf("failed audit: %+v", report)
	}
	t.Logf("verified independent namespaces: host=%+v child=%+v", report.Host, report.Child)
}
