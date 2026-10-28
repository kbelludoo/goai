// Package sandboxpolicy answers one question with one JSON document: may this
// host run untrusted code under GoAI's required controls?
//
// It is a gate, not an executor. Every check is read-only unless a caller
// explicitly asks for the placement probe, and an unknown answer is never
// treated as success: the policy denies by default. Denying is the safe
// outcome, because a host that silently runs untrusted code without cgroup
// limits is worse than a host that refuses to run it at all.
package sandboxpolicy

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// Protocol is the envelope version shared with the rest of GoAI.
const Protocol = "goai/0.2"

// defaultKillTimeout bounds how long cleanup waits for cgroup.kill to drain a
// cgroup before reporting ErrNotEmpty.
const defaultKillTimeout = 5 * time.Second

// Status is deliberately tri-state. "Unknown" exists so that a check which
// cannot be proven read-only (for example, whether clone3 accepts
// CLONE_INTO_CGROUP on this kernel) can never be confused with "OK".
type Status string

const (
	StatusOK      Status = "ok"
	StatusWarn    Status = "warn"
	StatusFail    Status = "fail"
	StatusUnknown Status = "unknown"
)

// Check is one precondition, with the stable code an agent branches on.
type Check struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Code   string `json:"code,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Limits is the aggregate budget requested for one validation run. Zero values
// mean "no policy configured", which is a failure, not "unlimited".
type Limits struct {
	MemoryMaxBytes int64 `json:"memory_max_bytes"`
	CPUQuotaUS     int64 `json:"cpu_quota_us"`
	CPUPeriodUS    int64 `json:"cpu_period_us"`
	PIDsMax        int64 `json:"pids_max"`
}

// Decision is the machine-readable verdict.
type Decision struct {
	Protocol string   `json:"protocol"`
	Mode     string   `json:"mode"`
	Allowed  bool     `json:"allowed"`
	Root     string   `json:"delegation_root,omitempty"`
	Checks   []Check  `json:"checks"`
	Reasons  []string `json:"reasons,omitempty"`
}

// Err denies execution. Callers must not interpret a partially passing
// decision as permission to run untrusted code.
func (d Decision) Err() error {
	if d.Allowed {
		return nil
	}
	if len(d.Reasons) == 0 {
		return errors.New("GOAI-POLICY-000: sandbox policy not satisfied")
	}
	return fmt.Errorf("sandbox policy not satisfied: %s", d.Reasons[0])
}

func (d *Decision) add(name string, status Status, code, detail string) {
	d.Checks = append(d.Checks, Check{Name: name, Status: status, Code: code, Detail: detail})
	if status == StatusFail {
		if code == "" {
			code = "GOAI-POLICY-001"
		}
		if detail == "" {
			d.Reasons = append(d.Reasons, code)
			return
		}
		d.Reasons = append(d.Reasons, code+": "+detail)
	}
}

// deny finalizes a decision: allowed only when no failure and no unknown
// remains. Warnings are informational and do not by themselves deny.
func (d *Decision) deny() {
	for _, check := range d.Checks {
		if check.Status == StatusFail || check.Status == StatusUnknown {
			d.Allowed = false
			return
		}
	}
	d.Allowed = true
}

// DefaultLimits is a conservative, explicitly named profile. It is never applied
// implicitly: callers must ask for "default" or state their own numbers, because
// an invisible budget is indistinguishable from a forgotten one.
func DefaultLimits() Limits {
	return Limits{MemoryMaxBytes: 512 << 20, CPUQuotaUS: 50000, CPUPeriodUS: 100000, PIDsMax: 100}
}

// ParseLimits reads "memory/cpu/pids" profiles, for example:
//
//	512MiB/50%/100     512 MiB, half a core on average, 100 tasks
//	2GiB/200%/64       two cores of quota, 64 tasks
//	default            DefaultLimits
//
// The empty string is an error: a missing policy is not an unlimited policy.
func ParseLimits(profile string) (Limits, error) {
	switch profile {
	case "":
		return Limits{}, errors.New("GOAI-POLICY-002: no limits profile given (try -limits default)")
	case "default":
		return DefaultLimits(), nil
	}
	parts := strings.Split(profile, "/")
	if len(parts) != 3 {
		return Limits{}, errors.New("GOAI-POLICY-003: limits profile must be memory/cpu/pids, e.g. 512MiB/50%/100")
	}
	memory, err := parseBytes(parts[0])
	if err != nil {
		return Limits{}, err
	}
	cpu, err := parsePercent(parts[1])
	if err != nil {
		return Limits{}, err
	}
	pids, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
	if err != nil || pids < 1 || pids > 1_000_000 {
		return Limits{}, errors.New("GOAI-POLICY-004: pids must be an integer between 1 and 1000000")
	}
	return Limits{MemoryMaxBytes: memory, CPUQuotaUS: cpu, CPUPeriodUS: 100000, PIDsMax: pids}, nil
}

func parseBytes(text string) (int64, error) {
	trimmed := strings.TrimSpace(text)
	units := []struct {
		suffix string
		scale  int64
	}{
		{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10},
		{"GB", 1_000_000_000}, {"MB", 1_000_000}, {"KB", 1_000},
		{"B", 1},
	}
	for _, unit := range units {
		if !strings.HasSuffix(trimmed, unit.suffix) {
			continue
		}
		number, err := strconv.ParseInt(strings.TrimSuffix(trimmed, unit.suffix), 10, 64)
		if err != nil || number < 1 {
			return 0, errors.New("GOAI-POLICY-005: invalid memory value " + text)
		}
		// Refuse nonsense budgets rather than letting cgroup validation find out.
		if number > math.MaxInt64/unit.scale {
			return 0, errors.New("GOAI-POLICY-005: memory value overflows " + text)
		}
		return number * unit.scale, nil
	}
	return 0, errors.New("GOAI-POLICY-005: memory needs a unit (KiB, MiB, GiB, KB, MB, GB)")
}

func parsePercent(text string) (int64, error) {
	trimmed := strings.TrimSpace(text)
	if !strings.HasSuffix(trimmed, "%") {
		return 0, errors.New("GOAI-POLICY-006: cpu must be a percentage of one core, e.g. 50%")
	}
	percent, err := strconv.ParseInt(strings.TrimSuffix(trimmed, "%"), 10, 64)
	if err != nil || percent < 1 || percent > 1000 {
		return 0, errors.New("GOAI-POLICY-006: cpu percentage must be between 1% and 1000%")
	}
	// cpu.max is quota per period; 100% of one core is 100000us per 100000us.
	return percent * 1000, nil
}
