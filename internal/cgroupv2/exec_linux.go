//go:build linux

package cgroupv2

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

var (
	// ErrExecutableChanged means the path no longer names the object that was
	// validated, or that object is not executable.
	ErrExecutableChanged = errors.New("GOAI-CGROUP-024: executable path does not match a validated regular file")
)

// atEmptyPath is AT_EMPTY_PATH: execute the file the descriptor refers to,
// ignoring the (empty) path argument.
const atEmptyPath = 0x1000

// oPath opens a file without read permission, purely to pin the inode.
const oPath = 0x200000

// openExecutable pins the executable object and validates *that object*.
//
// A path-based Stat followed by a path-based Exec is a time-of-check to
// time-of-use gap: swapping the file (or a directory component) in between runs
// code that was never validated. Here the descriptor is the subject of both the
// validation and the exec, so no swap can occur after the check.
func openExecutable(path string) (int, error) {
	if err := checkParentDirs(path); err != nil {
		return -1, err
	}
	fd, err := syscall.Open(path, oPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, errors.Join(ErrExecutableChanged, err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		syscall.Close(fd)
		return -1, errors.Join(ErrExecutableChanged, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&0111 == 0 {
		syscall.Close(fd)
		return -1, fmt.Errorf("%w: not a regular executable", ErrExecutableChanged)
	}
	return fd, nil
}

// checkParentDirs refuses an executable whose directory chain anyone but the
// owner can write. The descriptor protects the final object; this protects the
// lookup that produced it, which is the remaining window for an unprivileged
// swap of a parent directory.
func checkParentDirs(path string) error {
	dir := filepath.Dir(filepath.Clean(path))
	for {
		info, err := os.Lstat(dir)
		if err != nil {
			return errors.Join(ErrExecutableChanged, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("%w: %s is not a directory", ErrExecutableChanged, dir)
		}
		// A sticky world-writable directory (/tmp) is acceptable: others cannot
		// rename or delete entries they do not own. A plain 0777 directory is not.
		if info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("%w: %s is writable by group or other", ErrExecutableChanged, dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

// execveatFD replaces the current process image with the file behind fd.
//
// execveat(2) with AT_EMPTY_PATH is the only way to execute exactly the inode
// that was validated. There is no fallback to a path-based exec: if the kernel
// or the sandbox denies execveat, the launch fails and no workload runs.
func execveatFD(fd int, argv, env []string) error {
	if len(argv) == 0 {
		return ErrLaunchDenied
	}
	argvp, err := bytePtrs(argv)
	if err != nil {
		return errors.Join(ErrLaunchDenied, err)
	}
	envp, err := bytePtrs(env)
	if err != nil {
		return errors.Join(ErrLaunchDenied, err)
	}
	var emptyPath [1]byte // NUL; execveat ignores it under AT_EMPTY_PATH
	_, _, errno := syscall.RawSyscall6(syscall.SYS_EXECVEAT,
		uintptr(fd),
		uintptr(unsafe.Pointer(&emptyPath[0])),
		uintptr(unsafe.Pointer(&argvp[0])),
		uintptr(unsafe.Pointer(&envp[0])),
		atEmptyPath,
		0)
	// execveat only returns on failure.
	runtime.KeepAlive(argvp)
	runtime.KeepAlive(envp)
	runtime.KeepAlive(emptyPath)
	if errno != 0 {
		return fmt.Errorf("%w: execveat: %v", ErrLaunchDenied, errno)
	}
	return fmt.Errorf("%w: execveat returned without executing", ErrLaunchDenied)
}

// bytePtrs builds the NUL-terminated pointer array execveat expects.
func bytePtrs(args []string) ([]*byte, error) {
	ptrs := make([]*byte, len(args)+1)
	for i, arg := range args {
		if strings.IndexByte(arg, 0) >= 0 {
			return nil, errors.New("argument contains NUL")
		}
		ptr, err := syscall.BytePtrFromString(arg)
		if err != nil {
			return nil, err
		}
		ptrs[i] = ptr
	}
	return ptrs, nil
}
