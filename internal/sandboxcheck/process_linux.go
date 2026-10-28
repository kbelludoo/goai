//go:build linux

package sandboxcheck

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kbelludoo/goai/internal/supervisor"
)

// daemonProcess is identified by a CSPRNG invocation nonce and by the PID
// namespace inode, not by an unreliable shell grep or a namespace-local PID.
type daemonProcess struct {
	hostPID      int
	pidNamespace string
}

// findCanaryDaemons uses the Linux host-visible procfs to identify a trusted
// helper with the exact invocation token. Visibility is a deployment prerequisite;
// absence of an expected live process is a FAILURE, not proof of containment.
func findCanaryDaemons(procRoot, marker string) ([]daemonProcess, error) {
	if len(marker) != 64 {
		return nil, errors.New("invalid process canary marker")
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	matches := []daemonProcess{}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid < 2 {
			continue
		}
		b, err := os.ReadFile(filepath.Join(procRoot, entry.Name(), "cmdline"))
		if err != nil {
			continue
		} // processes can exit while iterating
		args := strings.Split(string(b), "\x00")
		hasDaemon, hasMarker := false, false
		for i, arg := range args {
			if arg == "--canary-daemon" {
				hasDaemon = true
			}
			if arg == "--canary-id" && i+1 < len(args) && args[i+1] == marker {
				hasMarker = true
			}
		}
		if !hasDaemon || !hasMarker {
			continue
		}
		namespace, err := os.Readlink(filepath.Join(procRoot, entry.Name(), "ns", "pid"))
		if err != nil {
			return nil, fmt.Errorf("cannot verify canary pid namespace: %w", err)
		}
		matches = append(matches, daemonProcess{hostPID: pid, pidNamespace: namespace})
	}
	return matches, nil
}

func processCanaryArgs(probe, dir, marker string) []string {
	return []string{
		"--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
		"--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
		"--dir", "/goai", "--ro-bind", probe, "/goai/probe",
		// Expose only a newly-created, private coordination directory.
		"--dir", "/goai/control", "--bind", dir, "/goai/control",
		"--clearenv", "--setenv", "HOME", "/tmp", "--setenv", "PATH", "/goai",
		"--chdir", "/", "--", "/goai/probe", "--process-audit", "--canary-id", marker,
		"--control", "/goai/control",
	}
}

func waitForMarker(ctx context.Context, path, marker string) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		b, err := os.ReadFile(path)
		if err == nil && strings.TrimSpace(string(b)) == marker {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// auditDaemon uses a controlled positive witness: FIRST confirm a setsid
// descendant is actually alive in an independent PID namespace; THEN release
// its parent and require no matching descendant after bwrap/supervisor exits.
// This is an empirical kernel integration test, not a mathematical security
// proof, and does not bound untrusted CPU, memory, PIDs or IO.
func auditDaemon(ctx context.Context, bwrap, binary string, hostNS HostNamespaces) error {
	if ctx == nil {
		return ErrUnavailable
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	marker := hex.EncodeToString(random[:])
	dir, err := os.MkdirTemp("", "goai-daemon-control-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}

	runCtx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	// Probe's descendant is deliberately detached from the *probe's* process
	// group. The supervisor still owns the bwrap process group on host.
	result := make(chan error, 1)
	go func() {
		output, err := supervisor.RunTrusted(runCtx, bwrap, processCanaryArgs(binary, dir, marker), "", supervisor.Limits{MaxOutputBytes: 4096})
		if err != nil {
			err = fmt.Errorf("bwrap process canary: %w: %s", err, output.Output)
		}
		result <- err
	}()
	// Avoid hanging if bwrap is immediately rejected; checks below time out.
	if err := waitForMarker(runCtx, filepath.Join(dir, "parent-ready"), marker); err != nil {
		cancel()
		<-result
		return errors.Join(ErrUnavailable, fmt.Errorf("daemon preflight did not start: %w", err))
	}
	live, err := findCanaryDaemons("/proc", marker)
	if err != nil {
		cancel()
		<-result
		return errors.Join(ErrCompromised, err)
	}
	if len(live) != 1 || live[0].pidNamespace == hostNS.PID {
		cancel()
		<-result
		return errors.Join(ErrCompromised, fmt.Errorf("canary was not visible as exactly one live, isolated process: %+v", live))
	}
	if err := os.WriteFile(filepath.Join(dir, "release"), []byte(marker), 0600); err != nil {
		cancel()
		<-result
		return err
	}
	// Require the bubblewrap parent to exit while the daemon is still within
	// its 8s safety bound; a stalled parent is a failed containment test.
	select {
	case err := <-result:
		if err != nil {
			return errors.Join(ErrCompromised, err)
		}
	case <-runCtx.Done():
		cancel()
		<-result
		return errors.Join(ErrCompromised, errors.New("bwrap failed to exit after releasing probe"))
	}
	remaining, err := findCanaryDaemons("/proc", marker)
	if err != nil {
		return errors.Join(ErrCompromised, err)
	}
	if len(remaining) > 0 {
		return errors.Join(ErrCompromised, fmt.Errorf("detached canary remains alive after bwrap exited: %+v", remaining))
	}
	return nil
}
