//go:build linux

package sandboxpolicy

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/kbelludoo/goai/internal/cgroupv2"
)

// Evaluate runs every read-only precondition. rootPath must be an
// administrator-delegated, process-free cgroup v2 directory; an empty value is
// reported as a configuration failure rather than silently falling back to the
// current cgroup (which is almost never delegable).
func Evaluate(rootPath string, limits Limits) Decision {
	d := Decision{Protocol: Protocol, Mode: "sandbox", Root: rootPath, Checks: []Check{}}

	// 1. Kernel exposes a usable cgroup v2 hierarchy at all.
	if _, err := cgroupv2.Discover(); err != nil {
		d.add("cgroup2_mount", StatusFail, "GOAI-CGROUP-001", err.Error())
	} else {
		d.add("cgroup2_mount", StatusOK, "", "cgroup2 found in /proc/self/mountinfo and /proc/self/cgroup")
	}

	// 2. The limits are a real policy, not an omission.
	converted := cgroupv2.Limits{
		MemoryMaxBytes: limits.MemoryMaxBytes,
		CPUQuotaUS:     limits.CPUQuotaUS,
		CPUPeriodUS:    limits.CPUPeriodUS,
		PIDsMax:        limits.PIDsMax,
	}
	if err := ValidateLimits(converted); err != nil {
		d.add("limits", StatusFail, "GOAI-CGROUP-003", err.Error())
	} else {
		d.add("limits", StatusOK, "", "memory, cpu and pids budgets are set")
	}

	// 3. A delegation root was named, and it is a trustworthy cgroup directory.
	if rootPath == "" {
		d.add("delegation_root", StatusFail, "GOAI-CGROUP-004",
			"no delegation root configured; set -root or GOAI_DELEGATION_ROOT to a delegated cgroup v2 directory")
		return d.finish()
	}
	root, err := cgroupv2.At(rootPath)
	if err != nil {
		d.add("delegation_root", StatusFail, "GOAI-CGROUP-004", err.Error())
		return d.finish()
	}
	d.add("delegation_root", StatusOK, "", "symlink-free directory inside the cgroup2 mount")

	// 4. The root holds no tasks, so controllers can be enabled for children.
	procs, err := os.ReadFile(filepath.Join(rootPath, "cgroup.procs"))
	switch {
	case err != nil:
		d.add("process_free_root", StatusFail, "GOAI-CGROUP-002", err.Error())
	case strings.TrimSpace(string(procs)) != "":
		d.add("process_free_root", StatusFail, "GOAI-CGROUP-005",
			"delegation root still holds tasks; move them out before enabling controllers")
	default:
		d.add("process_free_root", StatusOK, "", "no tasks in the delegation root")
	}

	// 5. Controllers are actually enabled for children (read-only check).
	if err := root.CheckDelegation(); err != nil {
		d.add("controllers_delegated", StatusFail, "GOAI-CGROUP-002",
			err.Error()+"; enable with cgroupv2.Root.EnableControllers on a process-free root")
	} else {
		d.add("controllers_delegated", StatusOK, "", "cpu, memory and pids enabled for children")
	}

	// 6. The isolation backend exists. Without it, cgroups limit but do not
	//    isolate: no filesystem, network or PID containment.
	if path, err := exec.LookPath("bwrap"); err != nil {
		d.add("bubblewrap", StatusFail, "GOAI-SANDBOX-001", "bwrap not found in PATH")
	} else {
		d.add("bubblewrap", StatusOK, "", path)
	}

	// 7. Atomic placement cannot be proven without starting a process, so it is
	//    reported as unknown here. Use ProbeAtomicPlacement with a trusted
	//    binary before treating it as satisfied.
	d.add("atomic_placement", StatusUnknown, "GOAI-CGROUP-007",
		"clone3(CLONE_INTO_CGROUP) is unproven; run ProbeAtomicPlacement with a trusted binary")

	return d.finish()
}

func (d Decision) finish() Decision {
	d.deny()
	return d
}

// ProbeAtomicPlacement replaces the "atomic_placement" unknown with evidence by
// preparing a throwaway cgroup and starting one trusted binary inside it.
//
// Only trustedPath is executed, never agent output, and the cgroup is destroyed
// afterwards. requiresDelegation means a host without delegation reports the
// real code (GOAI-CGROUP-002) instead of the generic unknown.
func ProbeAtomicPlacement(rootPath string, limits Limits, trustedPath string) (Decision, error) {
	d := Evaluate(rootPath, limits)
	if trustedPath == "" || !filepath.IsAbs(trustedPath) {
		return d, errors.New("a trusted absolute binary path is required for the placement probe")
	}
	if !d.Allowed && !onlyUnknown(d) {
		return d, d.Err()
	}
	root, err := cgroupv2.At(rootPath)
	if err != nil {
		return d, err
	}
	handle, err := root.Prepare(cgroupv2.Limits{
		MemoryMaxBytes: limits.MemoryMaxBytes,
		CPUQuotaUS:     limits.CPUQuotaUS,
		CPUPeriodUS:    limits.CPUPeriodUS,
		PIDsMax:        limits.PIDsMax,
	})
	if err != nil {
		return d, err
	}
	defer func() {
		_ = handle.Kill()
		_ = handle.WaitEmpty(defaultKillTimeout)
		_ = handle.Destroy()
	}()
	cmd := exec.Command(trustedPath)
	if err := handle.Start(cmd, nil); err != nil {
		if errors.Is(err, cgroupv2.ErrCloneIntoUnavailable) {
			d.replace("atomic_placement", StatusFail, "GOAI-CGROUP-007", err.Error())
			d.Allowed = false
			d.Reasons = append(d.Reasons, "GOAI-CGROUP-007: "+err.Error())
			return d, err
		}
		return d, err
	}
	d.replace("atomic_placement", StatusOK, "", "child was placed by clone3 before exec and membership verified")
	if err := handle.Kill(); err != nil {
		return d, err
	}
	if err := handle.WaitEmpty(defaultKillTimeout); err != nil {
		return d, err
	}
	d.Allowed = true
	return d, nil
}

func (d *Decision) replace(name string, status Status, code, detail string) {
	for i := range d.Checks {
		if d.Checks[i].Name == name {
			d.Checks[i] = Check{Name: name, Status: status, Code: code, Detail: detail}
			if status == StatusOK {
				reasons := d.Reasons[:0]
				for _, r := range d.Reasons {
					if !strings.HasPrefix(r, "GOAI-CGROUP-007") {
						reasons = append(reasons, r)
					}
				}
				d.Reasons = reasons
			}
			return
		}
	}
	d.add(name, status, code, detail)
}

func onlyUnknown(d Decision) bool {
	for _, check := range d.Checks {
		if check.Status == StatusFail {
			return false
		}
	}
	return true
}

// Enable turns on the required controllers for children of a delegation root.
//
// This is the only mutating operation in this package and it is never implicit:
// a caller asks for it because the alternative (a silent no-op on unavailable
// controllers) looks exactly like success. It refuses a root that still holds
// tasks, and it never chowns, chmods or reorganizes unrelated cgroups.
func Enable(rootPath string) error {
	root, err := cgroupv2.At(rootPath)
	if err != nil {
		return err
	}
	return root.EnableControllers()
}
