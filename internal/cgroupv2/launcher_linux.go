//go:build linux

package cgroupv2

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Launcher error codes live in their own block: GOAI-CGROUP-004 and -005 are
// already taken by the delegation-root errors in root_linux.go, and machine
// consumers branch on codes rather than on variable names.
var (
	ErrLaunchDenied = errors.New("GOAI-CGROUP-020: unverified cgroup; refusing exec")
	ErrJoinFailed   = errors.New("GOAI-CGROUP-021: failed to enter prepared cgroup")
)

const cgroup2SuperMagic = 0x63677270

// verifyTarget is deliberately strict: target must be a *direct child* of the
// caller's current v2 cgroup, and all three aggregate limits must be finite.
// This check does not authorize arbitrary command execution or establish a
// sandbox: only trusted GoAI code may invoke the launcher with a trusted argv.
func verifyTarget(target string) error {
	if target == "" || !filepath.IsAbs(target) || filepath.Clean(target) != target {
		return ErrLaunchDenied
	}
	info, err := os.Lstat(target)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrLaunchDenied, err)
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(target, &fs); err != nil || uint64(fs.Type) != cgroup2SuperMagic {
		return fmt.Errorf("%w: target is not on cgroup2", ErrLaunchDenied)
	}
	loc, err := Discover()
	if err != nil || filepath.Dir(target) != loc.Parent() {
		return fmt.Errorf("%w: target must be child of caller's current cgroup", ErrLaunchDenied)
	}
	for _, key := range []string{"memory.max", "pids.max"} {
		raw, err := os.ReadFile(filepath.Join(target, key))
		n, parseErr := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil || parseErr != nil || n == 0 {
			return fmt.Errorf("%w: %s must have finite positive limit", ErrLaunchDenied, key)
		}
	}
	cpu, err := os.ReadFile(filepath.Join(target, "cpu.max"))
	fields := strings.Fields(string(cpu))
	if err != nil || len(fields) != 2 {
		return fmt.Errorf("%w: cpu.max missing quota", ErrLaunchDenied)
	}
	quota, e1 := strconv.ParseUint(fields[0], 10, 64)
	period, e2 := strconv.ParseUint(fields[1], 10, 64)
	if e1 != nil || e2 != nil || quota == 0 || period == 0 {
		return fmt.Errorf("%w: cpu.max invalid", ErrLaunchDenied)
	}
	return nil
}

// joinSelf opens the existing cgroup.procs without O_CREATE, writes the current
// PID, and confirms the kernel reported the process in the destination.
func joinSelf(target string) error {
	file := filepath.Join(target, "cgroup.procs")
	fd, err := syscall.Open(file, syscall.O_WRONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.Join(ErrJoinFailed, err)
	}
	f := os.NewFile(uintptr(fd), file)
	_, writeErr := f.WriteString(strconv.Itoa(os.Getpid()) + "\n")
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return errors.Join(ErrJoinFailed, writeErr, closeErr)
	}
	loc, err := Discover()
	if err != nil || loc.Parent() != target {
		return fmt.Errorf("%w: kernel did not confirm membership", ErrJoinFailed)
	}
	return nil
}

// ExecPrepared is the privileged launch boundary. Only trusted launcher code
// can choose targetPath and argv. No untrusted workload is run until AFTER
// the process has joined and verified its cgroup. syscall.Exec preserves PID.
// The caller must still implement cgroup cleanup, bwrap namespaces, resource
// budget policy and process-tree shutdown. On success this never returns.
func ExecPrepared(groupPath, targetPath string, argv []string) error {
	if !filepath.IsAbs(targetPath) || len(argv) == 0 || argv[0] != targetPath {
		return ErrLaunchDenied
	}
	st, err := os.Stat(targetPath)
	if err != nil || st.IsDir() || st.Mode()&0111 == 0 {
		return errors.Join(ErrLaunchDenied, err)
	}
	return launchPrepared(groupPath, targetPath, argv, verifyTarget, joinSelf, syscall.Exec)
}

// launchPrepared enforces check -> self-migration -> exec, in that order.
// Dependencies are injectable ONLY to exercise sequencing in unit tests;
// production always uses the real cgroup kernel API and syscall.Exec.
func launchPrepared(groupPath, targetPath string, argv []string,
	check func(string) error, join func(string) error,
	replace func(string, []string, []string) error) error {
	if err := check(groupPath); err != nil {
		return err
	}
	if err := join(groupPath); err != nil {
		return err
	}
	// Strip host credentials/proxy settings. The real sandbox must also filter
	// mounts and inherited descriptors independently. No user env passthrough.
	env := []string{
		"PATH=/usr/bin:/bin", "HOME=/workspace", "TMPDIR=/tmp", "LANG=C",
		"GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "CGO_ENABLED=0",
	}
	return replace(targetPath, argv, env)
}
