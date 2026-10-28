# GoAI Sandbox Stage 5 — self-migration + bounded cgroup verification

**Status: draft. Not a sandbox validator, not connected to `txmanager`.**

The trusted Linux-only `goai-cgroup-exec` launcher performs:

1. Require an absolute, clean destination path, a real cgroup2 filesystem, a direct child of the launcher’s current cgroup, and finite positive `memory.max`, `cpu.max` and `pids.max` values.
2. Require an **absolute executable path** chosen by the trusted supervisor; no PATH lookup or shell evaluation is performed.
3. Write the launcher’s PID to the existing `cgroup.procs` (never create an ordinary file), then independently resolve `/proc/self/cgroup` and confirm it has entered that exact directory.
4. Replace the same process image using `syscall.Exec` with a minimal, fixed environment; the target and its descendants inherit the cgroup. Failure at any step aborts with exit code 126/127; no unconfined fallback exists.

The helper itself runs briefly before joining the cgroup, but it is trusted GoAI code; **no untrusted agent code is executed prior to confirmed membership**. This scheme does not provide a general `clone3` atomic process creation guarantee, nor does it isolate files, namespaces, credentials, descriptors, or hostile processes on its own. In particular, it is not yet integrated with Bubblewrap, process supervisors, or validators. The existing manager remains fail-closed.

The launcher's minimal environment is fixed: PATH, HOME, TMPDIR, LANG, GOTOOLCHAIN, GOPROXY, GOSUMDB and CGO_ENABLED. Policy must still clean any inherited file descriptors and restrict mounts; avoid passing bearer tokens in argv or environment. In production, the caller must also verify cgroup policies against its own configured budgets (a *finite* quota alone is not sufficient), ensure the group is empty and private, set appropriate mount and permissions, and implement robust teardown with `cgroup.kill` or equivalent.

## Verification

Regular CI (no privileges): `go test ./...`, `go test -race ./internal/cgroupv2`, and `go vet ./...` test launcher sequencing, denial before exec, environment scrubbing, PID-preserving execve as a separate mechanism, and rejection of a fake cgroup directory. These **do not prove kernel containment**.

Explicit Linux integration, only on a trusted disposable test machine with delegated cgroup v2:

```sh
GOAI_CGROUP_INTEGRATION=1 go test -count=1 -v ./internal/cgroupv2 -run '^TestCgroupContainmentRealOptIn$'
```

The opt-in test prepares a fresh cgroup with a 512 MiB memory cap, a half-core CPU quota, and `pids.max=32`, builds the trusted launcher and bounded process probe, launches the latter *via self-migration*, checks that it is actually in the prepared cgroup, starts **no more than 64** short-lived child processes and verifies that the kernel increments `pids.events:max`. This is a deliberately bounded test, **not an unbounded fork bomb**. Cleanup attempts cgroup removal and a controlled `cgroup.kill` on a unique test group if still occupied.

A requested opt-in test **fails** if delegation or installation is missing rather than claiming success. On this workspace `/sys/fs/cgroup` is read-only and not delegated; kernel integration has **not** been executed. Separately test Bubblewrap isolation and daemon cleanup on a suitable Linux system before exposing untrusted code.

## Security gaps before merging the complete sandbox chain

- Wire the launcher only to a privileged supervisor with a fixed resource policy; never allow an AI to supply target commands, cgroup paths or argv.
- Enforce filesystem and network policies with Bubblewrap or another reviewed runtime, then run independent host-observed network, filesystem and process canaries in the target kernel.
- Prevent time-of-check/time-of-use issues in directory and mount identity (e.g. stronger fd-based resolution), and test under adversarial filesystem mutations.
- Handle cgroup leaks, process termination, timeout/restart recovery and resource-event evidence across the full lifecycle.
- Bind validation evidence to the source revision, candidate digest, isolation policy and trusted execution instance before issuing commit capabilities.
- Existing single-file optimistic writer **does not** provide atomic compare-and-swap against noncooperating writers.
