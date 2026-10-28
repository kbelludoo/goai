//go:build linux

package isolationprobe

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// RunDaemonParent runs only as a trusted helper inside a PID namespace.
// It starts an independent session, confirms readiness, then waits for the
// host controller to permit the namespace's init process to exit.
// No agent-provided executable or shell is ever involved.
func RunDaemonParent(id, controlDir string) error {
	if !validCanaryID(id) {
		return errors.New("invalid canary ID")
	}
	cmd := exec.Command("/proc/self/exe", "--canary-daemon", "--canary-id", id, "--control", controlDir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout, cmd.Stderr, cmd.Stdin = nil, nil, nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start daemon: %w", err)
	}
	// This is deliberately not a group kill. The PID namespace must perform
	// cleanup even when the child has made a different session and group.
	if err := cmd.Process.Release(); err != nil {
		return err
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(filepath.Join(controlDir, "ready"))
		if err == nil && strings.TrimSpace(string(b)) == id {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	b, err := os.ReadFile(filepath.Join(controlDir, "ready"))
	if err != nil || strings.TrimSpace(string(b)) != id {
		return errors.New("canary daemon never became ready")
	}
	if err := os.WriteFile(filepath.Join(controlDir, "parent-ready"), []byte(id), 0600); err != nil {
		return err
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(filepath.Join(controlDir, "release"))
		if err == nil && strings.TrimSpace(string(b)) == id {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return errors.New("host never released process canary")
}

// RunDaemonChild is entered via exec of the same trusted binary; its unique ID
// remains in argv so the host can identify it through procfs independently of
// its namespace-relative PID. It exits by itself after a short safety bound.
func RunDaemonChild(id, controlDir string) error {
	if !validCanaryID(id) {
		return errors.New("invalid canary ID")
	}
	if err := os.WriteFile(filepath.Join(controlDir, "ready"), []byte(id), 0600); err != nil {
		return err
	}
	time.Sleep(8 * time.Second)
	return nil
}

func validCanaryID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, ch := range id {
		if ch < '0' || ch > '9' {
			if ch < 'a' || ch > 'f' {
				return false
			}
		}
	}
	return true
}
