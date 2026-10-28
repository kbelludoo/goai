//go:build linux

package cgroupv2

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var (
	// ErrNotADirectory means the caller-supplied delegation root is not a real
	// directory on the cgroup2 mount, or is reached through a symlink.
	ErrNotADirectory = errors.New("GOAI-CGROUP-004: delegation root is not a directory on the cgroup2 mount")
	// ErrBusyRoot means the delegation root holds tasks, so enabling controllers
	// for its children is impossible or affects unrelated workloads.
	ErrBusyRoot = errors.New("GOAI-CGROUP-005: delegation root is not process-free")
	// ErrControllerUnavailable means the delegation root does not expose a
	// required controller; enabling it would be a silent no-op.
	ErrControllerUnavailable = errors.New("GOAI-CGROUP-006: required controller not available at delegation root")
	// ErrCloneIntoUnavailable means the kernel or the Go runtime cannot place a
	// child into a cgroup atomically before exec.
	ErrCloneIntoUnavailable = errors.New("GOAI-CGROUP-007: atomic pre-exec cgroup placement unavailable (clone3 CLONE_INTO_CGROUP)")
)

// ValidateLimits reports whether a budget is usable, without touching the host.
func ValidateLimits(l Limits) error { return l.validate() }

// Root is an explicitly configured delegation root: a cgroup v2 directory that
// this process is allowed to subdivide.
//
// Discover() returns the *current* cgroup, which is rarely delegable. Under
// systemd, a service's processes live in `<unit>/init.scope`; that leaf cannot
// hand controllers to children, and enabling controllers on a cgroup that holds
// tasks is either EBUSY or a silent no-op. A Root is therefore never guessed
// from a UID or a path pattern: an administrator names it (for example a
// transient unit started with Delegate=yes).
type Root struct {
	mountpoint string
	path       string
}

// Path reports the delegation root, for diagnostics only.
func (r Root) Path() string { return r.path }

// Mountpoint reports the cgroup2 mount backing this root.
func (r Root) Mountpoint() string { return r.mountpoint }

// At resolves an administrator-supplied directory as a delegation root.
//
// The directory must already exist inside the canonical cgroup2 mount and must
// not be reached through a symlink. This function never creates, chowns or
// chmods host cgroups; it only refuses configurations it cannot trust.
func At(dir string) (Root, error) {
	if dir == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return Root{}, ErrNotADirectory
	}
	mountinfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return Root{}, errors.Join(ErrUnavailable, err)
	}
	_, mountpoint, err := cgroupMount(string(mountinfo))
	if err != nil {
		return Root{}, err
	}
	relative, err := filepath.Rel(mountpoint, dir)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return Root{}, ErrNotADirectory
	}
	if relative == "." {
		// The root of the hierarchy is the host's (or container's) own budget.
		// Subdividing it would make every GoAI limit depend on unrelated
		// workloads, so it must never be treated as a delegated subtree.
		return Root{}, errors.Join(ErrNotADirectory, errors.New("the cgroup2 mount root is not a delegation root"))
	}
	actualRoot, err := filepath.EvalSymlinks(mountpoint)
	if err != nil {
		return Root{}, errors.Join(ErrUnavailable, err)
	}
	actualDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return Root{}, errors.Join(ErrNotADirectory, err)
	}
	actualRelative, err := filepath.Rel(actualRoot, actualDir)
	if err != nil || actualRelative == ".." || strings.HasPrefix(actualRelative, ".."+string(filepath.Separator)) {
		return Root{}, ErrNotADirectory
	}
	info, err := os.Stat(actualDir)
	if err != nil || !info.IsDir() {
		return Root{}, ErrNotADirectory
	}
	// accessWrite is W_OK from <unistd.h>; syscall does not export it on Linux.
	const accessWrite = 0x2
	if err := syscall.Access(actualDir, accessWrite); err != nil {
		return Root{}, errors.Join(ErrNotDelegated, fmt.Errorf("delegation root not writable: %w", err))
	}
	return Root{mountpoint: mountpoint, path: dir}, nil
}

// EnableControllers turns on the required controllers for the root's children.
//
// Membership is checked FIRST: writing to cgroup.subtree_control of a cgroup
// that still holds tasks fails with EBUSY for available controllers and silently
// attaches nothing for unavailable ones. Only the three required controllers are
// enabled, because every enabled controller imposes the no-internal-process rule
// on this subtree.
func (r Root) EnableControllers() error {
	if r.path == "" || r.mountpoint == "" {
		return ErrInvalid
	}
	procs, err := os.ReadFile(filepath.Join(r.path, "cgroup.procs"))
	if err != nil {
		return errors.Join(ErrNotDelegated, err)
	}
	if strings.TrimSpace(string(procs)) != "" {
		return fmt.Errorf("%w: %s lists tasks", ErrBusyRoot, r.path)
	}
	available, err := os.ReadFile(filepath.Join(r.path, "cgroup.controllers"))
	if err != nil {
		return errors.Join(ErrNotDelegated, err)
	}
	have := tokenize(available)
	for _, name := range requiredControllers {
		if !have[name] {
			return fmt.Errorf("%w: %s", ErrControllerUnavailable, name)
		}
	}
	for _, name := range requiredControllers {
		if err := os.WriteFile(filepath.Join(r.path, "cgroup.subtree_control"), []byte("+"+name), 0644); err != nil {
			return errors.Join(ErrNotDelegated, fmt.Errorf("enable %s: %w", name, err))
		}
	}
	return r.CheckDelegation()
}

// CheckDelegation verifies, without modifying the host, that all required
// controllers are enabled for children of the root.
func (r Root) CheckDelegation() error {
	return CheckDelegation(Location{mountpoint: r.mountpoint, parent: r.path})
}

// Prepare creates an empty, random-named child of the root with every limit
// already applied, and returns a handle holding an open directory descriptor.
func (r Root) Prepare(limits Limits) (*Handle, error) {
	if r.path == "" || r.mountpoint == "" {
		return nil, ErrInvalid
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if err := r.CheckDelegation(); err != nil {
		return nil, err
	}
	name, err := randomName()
	if err != nil {
		return nil, err
	}
	// r.path was already validated by At: absolute, symlink-free and inside the
	// cgroup2 mount. The child name is 128 random bits, so it cannot be
	// guessed or pre-created by another process.
	path := filepath.Join(r.path, name)
	if err := os.Mkdir(path, 0700); err != nil {
		return nil, errors.Join(ErrNotDelegated, err)
	}
	h, err := openHandle(r.path, name)
	if err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	if err := h.applyLimits(limits); err != nil {
		_ = h.Destroy()
		return nil, err
	}
	return h, nil
}
