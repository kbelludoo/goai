// Package sandboxcheck performs defense-in-depth probes of a Bubblewrap
// invocation. Canaries are empirical tests, NOT mathematical security proofs.
// The package is not a validator, sandbox for arbitrary code, or an authority
// to mark a GoAI transaction approved. It must remain disconnected from TxManager
// until a reviewed isolated test executor and resource controls are available.
package sandboxcheck

import (
	"errors"
	"sync"

	"github.com/kbelludoo/goai/internal/isolationprobe"
)

var (
	ErrUnavailable = errors.New("GOAI-SANDBOX-001: required isolation backend unavailable")
	ErrCompromised = errors.New("GOAI-SANDBOX-002: isolation preflight failed")
	ErrQuarantined = errors.New("GOAI-SANDBOX-003: auditor is quarantined")
)

type HostNamespaces struct{ Net, Mount, PID string }
type Report struct {
	Host    HostNamespaces
	Child   isolationprobe.Observation
	Backend string
}

// Auditor owns failure state. A failed audit quarantines this instance.
// It is instantiated only by privileged GoAI code with a trusted probe binary.
type Auditor struct {
	mu          sync.Mutex
	quarantined bool
	probeBinary string
}

func NewAuditor(trustedProbeBinary string) (*Auditor, error) {
	if trustedProbeBinary == "" {
		return nil, errors.New("trusted probe binary required")
	}
	return &Auditor{probeBinary: trustedProbeBinary}, nil
}
func (a *Auditor) isQuarantined() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.quarantined
}
func (a *Auditor) quarantine() { a.mu.Lock(); a.quarantined = true; a.mu.Unlock() }
func (a *Auditor) Quarantined() bool {
	if a == nil {
		return true
	}
	return a.isQuarantined()
}

func assess(host HostNamespaces, child isolationprobe.Observation) error {
	if host.Net == "" || host.Mount == "" || host.PID == "" ||
		child.NetNamespace == "" || child.MountNamespace == "" || child.PIDNamespace == "" {
		return errors.Join(ErrCompromised, errors.New("missing namespace identity"))
	}
	if host.Net == child.NetNamespace || host.Mount == child.MountNamespace || host.PID == child.PIDNamespace {
		return errors.Join(ErrCompromised, errors.New("child shares a host namespace"))
	}
	if child.HostReachable || child.SentinelReadable {
		return errors.Join(ErrCompromised, errors.New("child accessed a controlled host-only resource"))
	}
	return nil
}
