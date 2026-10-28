//go:build linux && !amd64 && !arm64

package cgroupv2

// sysExecveat is unknown on this architecture, so descriptor-based execution is
// reported as unavailable instead of guessing a syscall number. Guessing here
// would risk invoking an unrelated kernel entry point.
const sysExecveat = -1
