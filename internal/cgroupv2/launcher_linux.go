//go:build linux

package cgroupv2

import (
	"errors"
	"fmt"
	"io"
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
	// ErrNotExclusive means the group was shared: it already held tasks, held
	// child cgroups, or gained another member between the empty check and the
	// join. Exclusivity is what makes a limit a budget for one workload.
	ErrNotExclusive = errors.New("GOAI-CGROUP-022: cgroup is not an exclusive, empty group")
	// ErrGroupNotOwned means someone other than us can write the group: a
	// different owner, or group/other write permission. Emptiness alone is a
	// snapshot, so ownership is the durable half of the property.
	ErrGroupNotOwned = errors.New("GOAI-CGROUP-023: cgroup is not owned by this user with private permissions")
)

const cgroup2SuperMagic = 0x63677270

// checkGroupIdentity validates the *object* rather than the path: a symlink
// swap or a rename after validation cannot change what the descriptor points
// to. It requires a real cgroup2 directory owned by this user with no group or
// other write permission.
func checkGroupIdentity(fd int) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return errors.Join(ErrLaunchDenied, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return fmt.Errorf("%w: not a directory", ErrLaunchDenied)
	}
	var fs syscall.Statfs_t
	if err := syscall.Fstatfs(fd, &fs); err != nil || uint64(fs.Type) != cgroup2SuperMagic {
		return fmt.Errorf("%w: not on cgroup2", ErrLaunchDenied)
	}
	if st.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("%w: owned by uid %d, not %d", ErrGroupNotOwned, st.Uid, os.Geteuid())
	}
	if st.Mode&0022 != 0 {
		return fmt.Errorf("%w: mode %04o allows group or other writes", ErrGroupNotOwned, st.Mode&07777)
	}
	return nil
}

// checkGroupState validates the *contents*: no pre-existing tasks and no child
// cgroups. Children are refused so the caller cannot present a subtree whose
// budget it configured elsewhere; the empty check is the same property one
// level down.
func checkGroupState(fd int) error {
	pids, err := readProcsAt(fd)
	if err != nil {
		return errors.Join(ErrLaunchDenied, err)
	}
	if len(pids) != 0 {
		return fmt.Errorf("%w: already holds %d task(s)", ErrNotExclusive, len(pids))
	}
	return checkNoChildGroupsAt(fd)
}

func readProcsAt(dirfd int) ([]int, error) {
	fd, err := syscall.Openat(dirfd, "cgroup.procs", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "cgroup.procs")
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 1<<16))
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

func readDirNamesAt(dirfd int) ([]string, error) {
	dup, err := syscall.Dup(dirfd)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(dup), "group")
	defer dir.Close()
	if _, err := dir.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return dir.Readdirnames(-1)
}

func checkNoChildGroupsAt(dirfd int) error {
	names, err := readDirNamesAt(dirfd)
	if err != nil {
		return errors.Join(ErrLaunchDenied, err)
	}
	for _, name := range names {
		fd, err := syscall.Openat(dirfd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			continue // not a directory (a cgroup pseudo-file, typically)
		}
		syscall.Close(fd)
		return fmt.Errorf("%w: contains child cgroup %q", ErrNotExclusive, name)
	}
	return nil
}

// verifyTarget is deliberately strict: target must be a *direct child* of the
// caller's current v2 cgroup, owned by the caller with private permissions, on
// cgroup2, with finite aggregate limits, no pre-existing tasks and no children.
// This check does not authorize arbitrary command execution or establish a
// sandbox: only trusted GoAI code may invoke the launcher with a trusted argv.
func verifyTarget(target string) error {
	if target == "" || !filepath.IsAbs(target) || filepath.Clean(target) != target {
		return ErrLaunchDenied
	}
	loc, err := Discover()
	if err != nil || filepath.Dir(target) != loc.Parent() {
		return fmt.Errorf("%w: target must be child of caller's current cgroup", ErrLaunchDenied)
	}
	fd, err := syscall.Open(target, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errors.Join(ErrLaunchDenied, err)
	}
	defer syscall.Close(fd)
	if err := checkGroupIdentity(fd); err != nil {
		return err
	}
	if err := checkGroupState(fd); err != nil {
		return err
	}
	for _, key := range []string{"memory.max", "pids.max"} {
		raw, err := readFileAt(fd, key)
		n, parseErr := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil || parseErr != nil || n == 0 {
			return fmt.Errorf("%w: %s must have finite positive limit", ErrLaunchDenied, key)
		}
	}
	cpu, err := readFileAt(fd, "cpu.max")
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

func readFileAt(dirfd int, name string) ([]byte, error) {
	fd, err := syscall.Openat(dirfd, name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, 1<<16))
}

// joinSelf opens the existing cgroup.procs without O_CREATE, writes the current
// PID, then requires two independent confirmations: the kernel reports this
// process in the destination, and the destination contains nobody else.
//
// Emptiness before the join is a snapshot; the process could have been joined by
// someone else in between. Emptiness *after* the join is the property that
// matters, and it is the one that makes a forged "contained" report impossible
// for a co-tenant process to produce.
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
	groupFD, err := syscall.Open(target, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errors.Join(ErrJoinFailed, err)
	}
	defer syscall.Close(groupFD)
	pids, err := readProcsAt(groupFD)
	if err != nil {
		return errors.Join(ErrJoinFailed, err)
	}
	if len(pids) != 1 || pids[0] != os.Getpid() {
		return fmt.Errorf("%w: group holds %v after join, expected only %d", ErrNotExclusive, pids, os.Getpid())
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
