//go:build linux && amd64

package cgroupv2

// sysExecveat is __NR_execveat on linux/amd64. Go's syscall package does not
// export it (x/sys/unix does), and this module deliberately has no dependencies.
const sysExecveat = 322
