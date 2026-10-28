//go:build linux

// Package cgroupv2 discovers and prepares fail-closed cgroup v2 resource
// budgets. It does not execute programs or attach PIDs: the future sandbox
// launcher must put a child inside the cgroup *before* that child can exec.
package cgroupv2

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	ErrUnavailable  = errors.New("GOAI-CGROUP-001: cgroup v2 mount or current path unavailable")
	ErrNotDelegated = errors.New("GOAI-CGROUP-002: required cgroup v2 controllers not delegated or not writable")
	ErrInvalid      = errors.New("GOAI-CGROUP-003: invalid cgroup limits or location")
)

var requiredControllers = []string{"cpu", "memory", "pids"}

// Location is resolved from the process cgroup namespace and cgroup2 mount.
// Internal fields prevent callers from constructing an arbitrary filesystem
// path and presenting it as a discovered cgroup.
type Location struct {
	mountpoint string
	parent     string
}

func (l Location) Parent() string { return l.parent }

// Limits apply to a cgroup's aggregate member tasks, not one Go goroutine.
// CPUQuotaUS is cpu.max quota per CPUPeriodUS (throttling, not a kill timer).
type Limits struct {
	MemoryMaxBytes int64
	CPUQuotaUS     int64
	CPUPeriodUS    int64
	PIDsMax        int64
}

func (l Limits) validate() error {
	if l.MemoryMaxBytes < 16*1024*1024 || l.CPUQuotaUS < 1000 ||
		l.CPUPeriodUS < 1000 || l.CPUPeriodUS > 1_000_000 ||
		l.CPUQuotaUS > 1_000_000_000 || l.PIDsMax < 1 || l.PIDsMax > 1_000_000 {
		return ErrInvalid
	}
	return nil
}

func decodeMountField(s string) (string, error) {
	// mountinfo escapes spaces, tabs, newlines and backslashes in path fields.
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+3 >= len(s) {
			return "", ErrUnavailable
		}
		chunk := s[i+1 : i+4]
		for j := 0; j < 3; j++ {
			if chunk[j] < '0' || chunk[j] > '7' {
				return "", ErrUnavailable
			}
		}
		n, _ := strconv.ParseUint(chunk, 8, 8)
		b.WriteByte(byte(n))
		i += 3
	}
	return b.String(), nil
}

func currentPath(content string) (string, error) {
	found := ""
	for _, ln := range strings.Split(content, "\n") {
		if ln == "" {
			continue
		}
		parts := strings.SplitN(ln, ":", 3)
		if len(parts) != 3 || parts[0] != "0" || parts[1] != "" {
			continue
		}
		if found != "" {
			return "", ErrUnavailable
		}
		found = parts[2]
	}
	if found == "" || !filepath.IsAbs(found) || filepath.Clean(found) != found {
		return "", ErrUnavailable
	}
	return found, nil
}

func cgroupMount(content string) (root, mountpoint string, err error) {
	// Require the canonical mountpoint: rejecting exotic layouts is safer
	// than accidentally selecting a writable fake directory or wrong mount.
	s := bufio.NewScanner(strings.NewReader(content))
	for s.Scan() {
		halves := strings.SplitN(s.Text(), " - ", 2)
		if len(halves) != 2 {
			continue
		}
		left, right := strings.Fields(halves[0]), strings.Fields(halves[1])
		if len(left) < 5 || len(right) < 1 || right[0] != "cgroup2" {
			continue
		}
		r, e1 := decodeMountField(left[3])
		m, e2 := decodeMountField(left[4])
		if e1 != nil || e2 != nil || m != "/sys/fs/cgroup" || !filepath.IsAbs(r) || filepath.Clean(r) != r {
			continue
		}
		if mountpoint != "" {
			return "", "", ErrUnavailable
		}
		root, mountpoint = r, m
	}
	if s.Err() != nil || mountpoint == "" {
		return "", "", ErrUnavailable
	}
	return root, mountpoint, nil
}

// Resolve locates the CURRENT cgroup in a mounted v2 hierarchy. It does not
// assert delegation. The kernel may remap paths in a cgroup namespace.
func Resolve(cgroupText, mountinfoText string) (Location, error) {
	path, err := currentPath(cgroupText)
	if err != nil {
		return Location{}, err
	}
	mountRoot, mountpoint, err := cgroupMount(mountinfoText)
	if err != nil {
		return Location{}, err
	}
	var relative string
	switch {
	case path == "/":
		relative = "." // possible cgroup-namespace-relative / view
	case mountRoot == "/":
		relative = strings.TrimPrefix(path, "/")
	case path == mountRoot:
		relative = "."
	case strings.HasPrefix(path, mountRoot+"/"):
		relative = strings.TrimPrefix(path, mountRoot+"/")
	default:
		return Location{}, ErrUnavailable
	}
	parent := filepath.Join(mountpoint, relative)
	rel, err := filepath.Rel(mountpoint, parent)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return Location{}, ErrUnavailable
	}
	// Avoid symlink tricks when a parent is unexpectedly redirected outside
	// the cgroup mount. Security also requires an actual cgroup2 mount.
	actualRoot, err := filepath.EvalSymlinks(mountpoint)
	if err != nil {
		return Location{}, errors.Join(ErrUnavailable, err)
	}
	actualParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return Location{}, errors.Join(ErrUnavailable, err)
	}
	actualRel, err := filepath.Rel(actualRoot, actualParent)
	if err != nil || actualRel == ".." || strings.HasPrefix(actualRel, ".."+string(filepath.Separator)) {
		return Location{}, ErrUnavailable
	}
	return Location{mountpoint: mountpoint, parent: parent}, nil
}

func Discover() (Location, error) {
	cgroup, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return Location{}, errors.Join(ErrUnavailable, err)
	}
	mountinfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return Location{}, errors.Join(ErrUnavailable, err)
	}
	return Resolve(string(cgroup), string(mountinfo))
}

func tokenize(data []byte) map[string]bool {
	result := map[string]bool{}
	for _, v := range strings.Fields(string(data)) {
		result[strings.TrimPrefix(v, "+")] = true
	}
	return result
}

// CheckDelegation observes controller delegation without editing the host's
// cgroup.subtree_control (which could have effects on unrelated workloads).
func CheckDelegation(loc Location) error {
	if loc.mountpoint == "" || loc.parent == "" {
		return ErrInvalid
	}
	enabled, err := os.ReadFile(filepath.Join(loc.parent, "cgroup.subtree_control"))
	if err != nil {
		return errors.Join(ErrNotDelegated, err)
	}
	available, err := os.ReadFile(filepath.Join(loc.parent, "cgroup.controllers"))
	if err != nil {
		return errors.Join(ErrNotDelegated, err)
	}
	e, a := tokenize(enabled), tokenize(available)
	for _, name := range requiredControllers {
		if !e[name] || !a[name] {
			return fmt.Errorf("%w: %s controller not enabled for children", ErrNotDelegated, name)
		}
	}
	return nil
}

// Group represents a prepared but EMPTY child cgroup. No PID attachment is
// exposed: moving an already-running PID is racy and unsafe for untrusted code.
type Group struct{ path string }

func (g *Group) Path() string {
	if g == nil {
		return ""
	}
	return g.path
}

func writeVerify(path, value string) error {
	if err := os.WriteFile(path, []byte(value), 0644); err != nil {
		return err
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(actual)) != strings.TrimSpace(value) {
		return fmt.Errorf("cgroup write verification mismatch: %s", filepath.Base(path))
	}
	return nil
}

// Prepare requires a delegated cgroup2 subtree and sets all three resource
// controls BEFORE a sandbox worker is allowed to start. The next increment
// must implement race-free pre-exec placement; Prepare never starts processes.
func Prepare(loc Location, limits Limits) (*Group, error) {
	return prepareWithMkdir(loc, limits, os.Mkdir)
}

func prepareWithMkdir(loc Location, limits Limits, mkdir func(string, os.FileMode) error) (_ *Group, err error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if err := CheckDelegation(loc); err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	path := filepath.Join(loc.parent, "goai-"+hex.EncodeToString(nonce[:]))
	if err := mkdir(path, 0700); err != nil {
		return nil, errors.Join(ErrNotDelegated, err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	// A genuine cgroup2 child automatically exposes cgroup.procs and controller
	// files. Check these *before* any write: os.WriteFile would otherwise
	// create ordinary files in a misidentified or test directory.
	for _, name := range []string{"cgroup.procs", "memory.max", "cpu.max", "pids.max"} {
		if _, e := os.Stat(filepath.Join(path, name)); e != nil {
			return nil, errors.Join(ErrNotDelegated, fmt.Errorf("not an initialized cgroup2 child (%s): %w", name, e))
		}
	}
	for _, item := range []struct{ name, value string }{
		{"memory.max", strconv.FormatInt(limits.MemoryMaxBytes, 10)},
		{"cpu.max", fmt.Sprintf("%d %d", limits.CPUQuotaUS, limits.CPUPeriodUS)},
		{"pids.max", strconv.FormatInt(limits.PIDsMax, 10)},
	} {
		if e := writeVerify(filepath.Join(path, item.name), item.value); e != nil {
			return nil, errors.Join(ErrNotDelegated, e)
		}
	}
	return &Group{path: path}, nil
}

// Remove only succeeds when the cgroup is empty. It does not silently kill
// processes; future launcher owns controlled termination before cleanup.
func (g *Group) Remove() error {
	if g == nil || g.path == "" {
		return ErrInvalid
	}
	return os.Remove(g.path)
}
