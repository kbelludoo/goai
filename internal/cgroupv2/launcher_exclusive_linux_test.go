//go:build linux

package cgroupv2

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// openGroup opens a directory the way verifyTarget does and returns its fd.
func openGroup(t *testing.T, path string) int {
	t.Helper()
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	return fd
}

// syntheticGroup builds a directory that looks like a cgroup state-wise, so the
// state checks can be exercised without privileges. It is NOT a cgroup and the
// identity checks must still refuse it (see TestIdentityRefusesNonCgroup).
func syntheticGroup(t *testing.T, procs string, children ...string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(procs), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range children {
		if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestStateRefusesNonEmptyGroup(t *testing.T) {
	dir := syntheticGroup(t, strconv.Itoa(os.Getpid())+"\n")
	err := checkGroupState(openGroup(t, dir))
	if !errors.Is(err, ErrNotExclusive) {
		t.Fatalf("a cgroup with tasks must be refused as not exclusive, got %v", err)
	}
}

func TestStateAcceptsEmptyLeaf(t *testing.T) {
	if err := checkGroupState(openGroup(t, syntheticGroup(t, ""))); err != nil {
		t.Fatalf("empty leaf group refused: %v", err)
	}
	// Whitespace-only cgroup.procs is empty, not one bogus member.
	if err := checkGroupState(openGroup(t, syntheticGroup(t, "  \n\n"))); err != nil {
		t.Fatalf("blank group refused: %v", err)
	}
}

func TestStateRefusesChildGroups(t *testing.T) {
	dir := syntheticGroup(t, "", "goai-child")
	err := checkGroupState(openGroup(t, dir))
	if !errors.Is(err, ErrNotExclusive) {
		t.Fatalf("a group with a child cgroup must be refused, got %v", err)
	}
}

func TestStateIgnoresPseudoFiles(t *testing.T) {
	// Real cgroups are mostly pseudo-files; only directories are children.
	dir := syntheticGroup(t, "")
	for _, name := range []string{"memory.max", "cpu.max", "pids.max", "cgroup.events"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("1\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkGroupState(openGroup(t, dir)); err != nil {
		t.Fatalf("pseudo-files treated as children: %v", err)
	}
}

func TestIdentityRefusesNonCgroup(t *testing.T) {
	dir := t.TempDir()
	err := checkGroupIdentity(openGroup(t, dir))
	if !errors.Is(err, ErrLaunchDenied) {
		t.Fatalf("ordinary directory accepted as cgroup2: %v", err)
	}
}

func TestIdentityRefusesPermissiveGroup(t *testing.T) {
	// The mode check is the durable half of exclusivity: an empty group that
	// another user can write is not a private budget.
	dir := syntheticGroup(t, "")
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	err := checkGroupIdentity(openGroup(t, dir))
	if !errors.Is(err, ErrGroupNotOwned) {
		t.Fatalf("group writable by others accepted: %v", err)
	}
	// Ownership and permissions are checked before the cgroup2 magic test, so a
	// permissive directory is reported as an ownership problem, not as "not a
	// cgroup". Verify that ordering explicitly.
	if errors.Is(err, ErrLaunchDenied) {
		t.Fatalf("permissive mode reported as a generic denial: %v", err)
	}
}

func TestIdentityRequiresCgroup2Magic(t *testing.T) {
	// /sys/fs/cgroup exists on Linux test hosts; it is a cgroup2 mount, so the
	// magic check passes and the failure (if any) must be about ownership or
	// mode rather than filesystem type.
	fd, err := syscall.Open("/sys/fs/cgroup", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Skip("no /sys/fs/cgroup")
	}
	defer syscall.Close(fd)
	var fs syscall.Statfs_t
	if err := syscall.Fstatfs(fd, &fs); err != nil {
		t.Skip("fstatfs unavailable")
	}
	if uint64(fs.Type) != cgroup2SuperMagic {
		t.Skip("host does not mount cgroup v2")
	}
	err = checkGroupIdentity(fd)
	if err != nil && errors.Is(err, ErrLaunchDenied) {
		t.Fatalf("real cgroup2 mount rejected as non-cgroup: %v", err)
	}
}

func TestVerifyTargetRejectsUntrustedShapes(t *testing.T) {
	// Path hygiene happens before any filesystem or cgroup access, so these
	// cases do not depend on host privileges.
	for _, target := range []string{"", "relative/path", "/sys/fs/cgroup/../cgroup", "/"} {
		if err := verifyTarget(target); !errors.Is(err, ErrLaunchDenied) {
			t.Errorf("%q accepted: %v", target, err)
		}
	}
}
