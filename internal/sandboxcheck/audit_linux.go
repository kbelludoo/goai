//go:build linux

package sandboxcheck

import (
	"context"
	"crypto/rand"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kbelludoo/goai/internal/isolationprobe"
	"github.com/kbelludoo/goai/internal/supervisor"
)

func readHostNamespaces() (HostNamespaces, error) {
	var h HostNamespaces
	var err error
	if h.Net, err = os.Readlink("/proc/self/ns/net"); err != nil {
		return h, err
	}
	if h.Mount, err = os.Readlink("/proc/self/ns/mnt"); err != nil {
		return h, err
	}
	if h.PID, err = os.Readlink("/proc/self/ns/pid"); err != nil {
		return h, err
	}
	return h, nil
}

// requireStaticProbe avoids binding host libraries or /usr into the sandbox.
// Callers are responsible for provisioning and protecting the trusted binary.
func requireStaticProbe(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absolute, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(absolute)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0111 == 0 || fi.Mode().Perm()&0022 != 0 {
		return "", errors.New("trusted helper must be a non-group-writable executable")
	}
	f, err := elf.Open(absolute)
	if err != nil {
		return "", fmt.Errorf("trusted helper must be an ELF binary: %w", err)
	}
	defer f.Close()
	if f.Machine != elf.EM_X86_64 && f.Machine != elf.EM_AARCH64 {
		return "", errors.New("unsupported trusted helper architecture")
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return "", errors.New("trusted probe must be statically linked (build with CGO_ENABLED=0)")
		}
	}
	return absolute, nil
}

// bwrapArgs deliberately mounts only the trusted static probe, a private tmpfs,
// proc and dev. It does NOT mount the developer's project, HOME, /usr or /tmp.
func bwrapArgs(probeBinary, hostURL, sentinelPath string) []string {
	return []string{
		"--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
		"--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
		"--dir", "/goai", "--ro-bind", probeBinary, "/goai/probe",
		"--clearenv", "--setenv", "HOME", "/tmp", "--setenv", "PATH", "/goai",
		"--chdir", "/", "--", "/goai/probe", "--host-url", hostURL, "--sentinel", sentinelPath,
	}
}

// Audit exercises a trusted helper INSIDE Bubblewrap. It does not execute AI
// code, and cannot be used to authorize commits or bypass security policies.
// Any failure (including missing bwrap/disabled namespaces) quarantines this
// Auditor. Creating a new Auditor is a privileged administrative action.
func (a *Auditor) Audit(ctx context.Context) (report Report, err error) {
	if a == nil {
		return Report{}, ErrUnavailable
	}
	if a.isQuarantined() {
		return Report{}, ErrQuarantined
	}
	// Any failure below disallows subsequent probes through this instance.
	defer func() {
		if err != nil {
			a.quarantine()
		}
	}()
	if ctx == nil {
		return Report{}, errors.Join(ErrUnavailable, errors.New("nil context"))
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return Report{}, errors.Join(ErrUnavailable, err)
	}
	binary, err := requireStaticProbe(a.probeBinary)
	if err != nil {
		return Report{}, errors.Join(ErrUnavailable, err)
	}
	hostNS, err := readHostNamespaces()
	if err != nil {
		return Report{}, errors.Join(ErrUnavailable, err)
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return Report{}, err
	}
	secret := hex.EncodeToString(nonce[:])
	// httptest.NewServer binds host loopback (not public network interfaces).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "HOST_REACHABLE:"+secret)
	}))
	defer server.Close()
	tmpdir, err := os.MkdirTemp("/tmp", "goai-host-sentinel-")
	if err != nil {
		return Report{}, err
	}
	defer os.RemoveAll(tmpdir)
	sentinel := filepath.Join(tmpdir, "probe")
	if err = os.WriteFile(sentinel, []byte(secret), 0600); err != nil {
		return Report{}, err
	}
	// Positive host controls: prove the endpoint and file are accessible to
	// the current host process before interpreting a child failure.
	hostObs, err := isolationprobe.Run(server.URL, sentinel)
	if err != nil || !hostObs.HostReachable || !hostObs.SentinelReadable {
		return Report{}, errors.Join(ErrUnavailable, errors.New("host positive controls failed"), err)
	}
	if hostObs.NetNamespace != hostNS.Net || hostObs.MountNamespace != hostNS.Mount || hostObs.PIDNamespace != hostNS.PID {
		return Report{}, errors.Join(ErrUnavailable, errors.New("inconsistent host namespace baseline"))
	}
	runCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := supervisor.RunTrusted(runCtx, bwrapPath, bwrapArgs(binary, server.URL, sentinel), "", supervisor.Limits{MaxOutputBytes: 8 * 1024})
	if err != nil {
		return Report{}, errors.Join(ErrUnavailable, fmt.Errorf("bwrap preflight: %w: %s", err, output.Output))
	}
	if output.OutputTruncated {
		return Report{}, errors.Join(ErrCompromised, errors.New("probe output truncated"))
	}
	dec := json.NewDecoder(strings.NewReader(output.Output))
	dec.DisallowUnknownFields()
	var child isolationprobe.Observation
	if err := dec.Decode(&child); err != nil {
		return Report{}, errors.Join(ErrCompromised, fmt.Errorf("invalid probe response: %w", err))
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Report{}, errors.Join(ErrCompromised, errors.New("unexpected trailing probe data"))
	}
	if err := assess(hostNS, child); err != nil {
		return Report{}, err
	}
	return Report{Host: hostNS, Child: child, Backend: "bubblewrap"}, nil
}
