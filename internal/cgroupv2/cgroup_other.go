//go:build !linux

package cgroupv2

import "errors"

var (
	ErrUnavailable  = errors.New("GOAI-CGROUP-001: cgroup v2 unavailable on this platform")
	ErrNotDelegated = errors.New("GOAI-CGROUP-002: cgroup v2 not available")
	ErrInvalid      = errors.New("GOAI-CGROUP-003: invalid configuration")
)

type Location struct{}

func (Location) Parent() string { return "" }

type Limits struct {
	MemoryMaxBytes int64
	CPUQuotaUS     int64
	CPUPeriodUS    int64
	PIDsMax        int64
}

type Group struct{}

func (*Group) Path() string                    { return "" }
func (*Group) Remove() error                   { return ErrUnavailable }
func Discover() (Location, error)              { return Location{}, ErrUnavailable }
func CheckDelegation(Location) error           { return ErrUnavailable }
func Prepare(Location, Limits) (*Group, error) { return nil, ErrUnavailable }
