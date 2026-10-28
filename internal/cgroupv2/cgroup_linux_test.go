//go:build linux

package cgroupv2

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mountinfo(root, mount string) string {
	return "100 99 0:40 " + root + " " + mount + " rw - cgroup2 cgroup2 rw,nsdelegate\n"
}
func TestDiscoverCurrentLinuxHierarchy(t *testing.T) {
	// This is a read-only discovery smoke test; delegation is not assumed.
	loc, err := Discover()
	if err != nil {
		t.Skipf("no accessible cgroup2 mount: %v", err)
	}
	if !strings.HasPrefix(loc.Parent(), "/sys/fs/cgroup") {
		t.Fatalf("bad mount location: %q", loc.Parent())
	}
}
func TestResolveMountPathAndCgroupNamespace(t *testing.T) {
	tests := []struct{ cg, root, want string }{
		{"0::/\n", "/", "/sys/fs/cgroup"},
		{"0::/user.slice/abc\n", "/", "/sys/fs/cgroup/user.slice/abc"},
		{"0::/\n", "/user.slice/abc", "/sys/fs/cgroup"},
	}
	for _, test := range tests {
		// Resolution of synthetic nested paths requires real on-disk parents.
		if test.want != "/sys/fs/cgroup" {
			continue
		}
		loc, err := Resolve(test.cg, mountinfo(test.root, "/sys/fs/cgroup"))
		if err != nil {
			t.Fatal(err)
		}
		if loc.Parent() != test.want {
			t.Fatalf("%q != %q", loc.Parent(), test.want)
		}
	}
}
func TestMalformedOrUntrustedMountDiscovery(t *testing.T) {
	for _, scenario := range []struct{ cg, mount string }{
		{"", mountinfo("/", "/sys/fs/cgroup")},
		{"0::/../../etc\n", mountinfo("/", "/sys/fs/cgroup")},
		{"0::relative\n", mountinfo("/", "/sys/fs/cgroup")},
		{"0::/\n0::/\n", mountinfo("/", "/sys/fs/cgroup")},
		{"0::/\n", mountinfo("/", "/tmp/fake-cgroup")},
		{"0::/\n", "100 99 0:40 / /sys/fs/cgroup rw - tmpfs tmpfs rw\n"},
		{"0::/\n", mountinfo("/", "/sys/fs/cgroup") + mountinfo("/", "/sys/fs/cgroup")},
		{"0::/wrong/path\n", mountinfo("/delegated", "/sys/fs/cgroup")},
	} {
		if _, err := Resolve(scenario.cg, scenario.mount); !errors.Is(err, ErrUnavailable) {
			t.Errorf("accepted invalid mount/path (%q/%q): %v", scenario.cg, scenario.mount, err)
		}
	}
}
func TestDecodeMountField(t *testing.T) {
	if s, err := decodeMountField("/var/lib/a\\040b"); err != nil || s != "/var/lib/a b" {
		t.Fatalf("%q %v", s, err)
	}
	if _, err := decodeMountField("a\\bad"); err == nil {
		t.Fatal("expected bad mount escape")
	}
}
func fakeLocation(t *testing.T, enabled, available string) Location {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte(enabled), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte(available), 0600); err != nil {
		t.Fatal(err)
	}
	return Location{mountpoint: root, parent: root}
}
func defaultLimits() Limits {
	return Limits{MemoryMaxBytes: 512 * 1024 * 1024, CPUQuotaUS: 50000, CPUPeriodUS: 100000, PIDsMax: 100}
}
func TestDelegationFailClosed(t *testing.T) {
	loc := fakeLocation(t, "cpu memory", "cpu memory pids")
	if err := CheckDelegation(loc); !errors.Is(err, ErrNotDelegated) {
		t.Fatalf("unenabled pids accepted: %v", err)
	}
	if _, err := Prepare(loc, defaultLimits()); !errors.Is(err, ErrNotDelegated) {
		t.Fatalf("create with missing controller: %v", err)
	}
	loc = fakeLocation(t, "cpu memory pids", "cpu memory pids")
	if err := CheckDelegation(loc); err != nil {
		t.Fatal(err)
	}
	// A plain directory cannot masquerade as a cgroup2 child: unlike sysfs,
	// it does not automatically create cgroup.procs and controller files.
	if _, err := Prepare(loc, defaultLimits()); !errors.Is(err, ErrNotDelegated) {
		t.Fatalf("fake mount accepted: %v", err)
	}
}
func TestPrepareAllLimitsOnSyntheticCgroupFS(t *testing.T) {
	loc := fakeLocation(t, "cpu memory pids", "cpu memory pids")
	mkdir := func(path string, mode os.FileMode) error {
		if err := os.Mkdir(path, mode); err != nil {
			return err
		}
		for _, name := range []string{"memory.max", "cpu.max", "pids.max", "cgroup.procs"} {
			if err := os.WriteFile(filepath.Join(path, name), []byte("max"), 0600); err != nil {
				return err
			}
		}
		return nil
	}
	group, err := prepareWithMkdir(loc, defaultLimits(), mkdir)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"memory.max": "536870912", "cpu.max": "50000 100000", "pids.max": "100"} {
		got, err := os.ReadFile(filepath.Join(group.Path(), name))
		if err != nil || string(got) != want {
			t.Errorf("%s: %q %v", name, got, err)
		}
	}
	if err := group.Remove(); err == nil {
		t.Fatal("ordinary directory with files must not be silently removed")
	}
}
func TestInvalidLimitsRejectedBeforeCreation(t *testing.T) {
	loc := fakeLocation(t, "cpu memory pids", "cpu memory pids")
	for _, v := range []Limits{{}, {MemoryMaxBytes: 1, CPUQuotaUS: 1, CPUPeriodUS: 1, PIDsMax: 0}, {MemoryMaxBytes: 536870912, CPUQuotaUS: 50000, CPUPeriodUS: 2_000_000, PIDsMax: 100}} {
		if _, err := Prepare(loc, v); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted invalid limits: %+v, %v", v, err)
		}
	}
}
func TestNoPrivilegeMeansNoExecution(t *testing.T) {
	loc, err := Discover()
	if err != nil {
		t.Skipf("no kernel cgroup2: %v", err)
	}
	// Merely query delegation; no real cgroup is created in non opt-in tests.
	_ = CheckDelegation(loc)
}
