# Issue #2 — process supervisor only (NOT a sandbox)

This incremental implementation adds `internal/supervisor.RunTrusted` for
**trusted programs only**. It creates a Linux process group, sends SIGKILL
to that group on cancellation and ordinary parent exit, and caps captured
output in memory. Tests demonstrate cleanup for cooperative descendants in
the same group. No AI-generated tests or scripts are allowed through this
API. Unsupported OS builds explicitly refuse to run.

## Security non-guarantees

- A child can escape its inherited group with `setsid` / `setpgid`;
  killing a group is not killing an arbitrary process tree.
- A process group does not restrict network, filesystem, environment,
  syscalls, CPU, memory, PIDs or output volume. In-memory output capture
  limits only retained diagnostics, not a child's resource consumption.
- `cmd.Wait`/PID reuse and unexpected descendants make process-group
  cleanup best-effort, not a hard kernel guarantee. A future sandbox
  should use PID namespace + properly configured init/reaper, cgroups v2
  / container cleanup, and enforceable process limits.
- A canary is a useful integration test, **not a mathematical proof**:
  failed TCP connects might be ordinary connectivity failures, and host
  `/etc/passwd` may intentionally be visible. Use unique host-only sentinels,
  controlled egress endpoints, and negative controls in the same sandbox
  policy that will execute untrusted code.
- `unshare` by itself does not provide filesystem containment: mount
  namespace isolation requires a correct mount tree/pivot_root policy.
  Do not silently fall back to host execution if unprivileged namespaces,
  seccomp or cgroup policies cannot be enforced.

## Acceptance for a later trusted validator

Select a maintained isolation backend (`bwrap`, gVisor, rootless OCI, etc.)
with explicit capability requirements. Deny network, mount only an approved
read-only toolchain plus a disposable workspace, prohibit host credentials,
apply CPU/memory/PID caps, collect bound gate evidence, and run adversarial
isolation tests. The trusted validator must be privileged internal GoAI
code, not agent-supplied JSON. Until that is done, the public TxManager
still rejects approval (`ErrValidatorUnavailable`).

## Tests

`go test ./internal/supervisor -count=1`
`go test -race ./internal/supervisor -count=1`
`go vet ./...`
