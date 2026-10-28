//go:build linux

package cgroupv2

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	// ErrNotEmpty means a cgroup still held tasks or children when it was
	// expected to be empty. Cleanup failures are never reported as success.
	ErrNotEmpty = errors.New("GOAI-CGROUP-008: cgroup still contains tasks or children")
	// ErrPlacementUnverified means the kernel accepted the clone but the child
	// is not the single member of the prepared cgroup. The child is killed.
	ErrPlacementUnverified = errors.New("GOAI-CGROUP-010: child membership in cgroup could not be verified")
	// ErrEscaped means a process that was placed in the cgroup is no longer a
	// member. This is detection, not prevention: it is what a process can do
	// when it may write the delegation root's cgroup.procs, which is why the
	// sandbox must run under a different UID than the GoAI service.
	ErrEscaped = errors.New("GOAI-CGROUP-011: validated process left its cgroup")
)

// Handle is a prepared, EMPTY child cgroup with an open directory descriptor.
//
// The descriptor is the security primitive: it survives path renames and cannot
// be retargeted by writing a different path later. It is opened with O_CLOEXEC
// so it is not inherited by the child.
type Handle struct {
	path   string
	parent string
	dir    *os.File

	mu     sync.Mutex
	closed bool
}

func randomName() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return "goai-" + hex.EncodeToString(nonce[:]), nil
}

func openHandle(parent, name string) (*Handle, error) {
	path := filepath.Join(parent, name)
	// O_DIRECTORY|O_CLOEXEC, not O_PATH: CLONE_INTO_CGROUP needs a usable cgroup
	// descriptor and rejects O_PATH descriptors with EBADF.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.Join(ErrNotDelegated, err)
	}
	return &Handle{path: path, parent: parent, dir: os.NewFile(uintptr(fd), name)}, nil
}

// Path reports the cgroup directory, for diagnostics only.
func (h *Handle) Path() string {
	if h == nil {
		return ""
	}
	return h.path
}

func (h *Handle) fd() (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.dir == nil {
		return -1, ErrInvalid
	}
	return int(h.dir.Fd()), nil
}

func (h *Handle) applyLimits(limits Limits) error {
	// A genuine cgroup2 child exposes these pseudo-files. Checking before the
	// first write prevents os.WriteFile from creating ordinary files in a
	// misidentified directory.
	for _, name := range []string{"cgroup.procs", "memory.max", "cpu.max", "pids.max"} {
		if _, err := os.Stat(filepath.Join(h.path, name)); err != nil {
			return errors.Join(ErrNotDelegated, fmt.Errorf("not an initialized cgroup2 child (%s): %w", name, err))
		}
	}
	for _, item := range []struct{ name, value string }{
		{"memory.max", strconv.FormatInt(limits.MemoryMaxBytes, 10)},
		{"cpu.max", fmt.Sprintf("%d %d", limits.CPUQuotaUS, limits.CPUPeriodUS)},
		{"pids.max", strconv.FormatInt(limits.PIDsMax, 10)},
	} {
		if err := writeVerify(filepath.Join(h.path, item.name), item.value); err != nil {
			return errors.Join(ErrNotDelegated, err)
		}
	}
	return nil
}

// Procs lists the PIDs currently in the cgroup, in file order.
func (h *Handle) Procs() ([]int, error) {
	data, err := os.ReadFile(filepath.Join(h.path, "cgroup.procs"))
	if err != nil {
		return nil, err
	}
	pids := []int{}
	for _, field := range strings.Fields(string(data)) {
		pid, err := strconv.Atoi(field)
		if err != nil {
			return nil, fmt.Errorf("unparseable cgroup.procs entry %q", field)
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

// Start launches cmd so that it is a member of this cgroup BEFORE it can exec.
//
// Placement happens inside clone3(CLONE_INTO_CGROUP): the kernel creates the
// child directly in this cgroup, so no userspace window exists in which
// untrusted code could fork outside the limits. The Go runtime does not fall
// back to "start, then write the PID": if clone3 is unavailable the launch
// fails with ErrCloneIntoUnavailable instead of running the child unlimited.
//
// attrs may carry caller requirements (namespaces, credentials, process group)
// but must not already set cgroup placement, so nothing is silently overridden.
// After a successful start, membership is verified; a mismatch kills the child
// and returns ErrPlacementUnverified.
func (h *Handle) Start(cmd *exec.Cmd, attrs *syscall.SysProcAttr) error {
	if cmd == nil || h == nil {
		return ErrInvalid
	}
	if cmd.Process != nil {
		return errors.Join(ErrInvalid, errors.New("command already started"))
	}
	fd, err := h.fd()
	if err != nil {
		return err
	}
	if attrs != nil && (attrs.UseCgroupFD || attrs.CgroupFD != 0) {
		return errors.Join(ErrInvalid, errors.New("SysProcAttr already sets cgroup placement"))
	}
	inherited := &syscall.SysProcAttr{}
	if attrs != nil {
		*inherited = *attrs
	}
	inherited.UseCgroupFD = true
	inherited.CgroupFD = fd
	cmd.SysProcAttr = inherited
	if err := cmd.Start(); err != nil {
		switch {
		case errors.Is(err, syscall.ENOSYS), errors.Is(err, syscall.EINVAL),
			errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM),
			errors.Is(err, syscall.EBADF), errors.Is(err, syscall.ENOENT):
			return errors.Join(ErrCloneIntoUnavailable, err)
		}
		return err
	}
	if err := h.VerifyContains(cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return err
	}
	return nil
}

// VerifyContains checks that pid is the only member of the cgroup.
//
// Call it after start and again before approving a candidate: a confined
// process that can write the delegation root's cgroup.procs can move itself out
// of the budget, and cgroup v2 itself cannot prevent that. Prevention requires
// UID separation (the confined process must not be the GoAI service's user).
func (h *Handle) VerifyContains(pid int) error {
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		pids, err := h.Procs()
		if err != nil {
			return errors.Join(ErrPlacementUnverified, err)
		}
		switch {
		case len(pids) == 1 && pids[0] == pid:
			return nil
		case len(pids) == 0:
			return errors.Join(ErrPlacementUnverified, errors.New("cgroup is empty; nothing was observed inside it"))
		case len(pids) > 1:
			return fmt.Errorf("%w: cgroup has %d members (%v), expected only %d", ErrPlacementUnverified, len(pids), pids, pid)
		case !contains(pids, pid):
			return fmt.Errorf("%w: pid %d absent; found %v", ErrPlacementUnverified, pid, pids)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w: transient membership %v", ErrPlacementUnverified, pids)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func contains(pids []int, pid int) bool {
	for _, candidate := range pids {
		if candidate == pid {
			return true
		}
	}
	return false
}

// Kill terminates every task in the cgroup with cgroup.kill, which is atomic
// with respect to fork: a task cannot escape by racing the write. Kernels older
// than 5.14 lack cgroup.kill and get ErrUnavailable, never a silent no-op.
func (h *Handle) Kill() error {
	if h == nil {
		return ErrInvalid
	}
	if _, err := h.fd(); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(h.path, "cgroup.kill"), []byte("1"), 0644); err != nil {
		return errors.Join(ErrUnavailable, fmt.Errorf("cgroup.kill: %w", err))
	}
	return nil
}

// WaitEmpty polls cgroup.procs until the cgroup has no tasks or timeout expires.
func (h *Handle) WaitEmpty(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		pids, err := h.Procs()
		if err != nil {
			return err
		}
		if len(pids) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w: %d tasks remain", ErrNotEmpty, len(pids))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Destroy closes the descriptor and removes the cgroup. It is idempotent and
// returns ErrNotEmpty instead of silently leaving a non-empty directory.
func (h *Handle) Destroy() error {
	if h == nil {
		return ErrInvalid
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	dir := h.dir
	h.mu.Unlock()

	var closeErr error
	if dir != nil {
		closeErr = dir.Close()
	}
	if err := os.Remove(h.path); err != nil {
		if errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, syscall.EBUSY) {
			return errors.Join(ErrNotEmpty, err, closeErr)
		}
		return errors.Join(err, closeErr)
	}
	return closeErr
}
