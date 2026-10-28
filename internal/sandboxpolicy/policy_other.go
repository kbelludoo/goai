//go:build !linux

package sandboxpolicy

import "errors"

// Evaluate denies on every non-Linux platform. There is no cgroup v2, no
// Bubblewrap and therefore no evidence that untrusted code would be contained;
// "not applicable" must never read as "allowed".
func Evaluate(rootPath string, limits Limits) Decision {
	d := Decision{
		Protocol: Protocol,
		Mode:     "sandbox",
		Root:     rootPath,
		Checks:   []Check{},
	}
	d.add("cgroup2_mount", StatusFail, "GOAI-CGROUP-001", "cgroup v2 and Bubblewrap are Linux-only")
	d.Allowed = false
	return d
}

// ProbeAtomicPlacement cannot produce evidence off Linux.
func ProbeAtomicPlacement(rootPath string, limits Limits, trustedPath string) (Decision, error) {
	d := Evaluate(rootPath, limits)
	return d, errors.New("atomic pre-exec placement requires Linux")
}

// Enable cannot succeed off Linux: cgroup v2 does not exist here.
func Enable(rootPath string) error {
	return errors.New("GOAI-CGROUP-001: cgroup v2 is Linux-only")
}
