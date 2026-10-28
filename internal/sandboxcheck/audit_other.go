//go:build !linux

package sandboxcheck

import "context"

// Audit requires Linux kernel namespaces; never silently fall back to host.
func (a *Auditor) Audit(_ context.Context) (Report, error) {
	if a != nil {
		a.quarantine()
	}
	return Report{}, ErrUnavailable
}
