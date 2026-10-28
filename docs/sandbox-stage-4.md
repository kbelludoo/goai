# GoAI sandbox Issue #2 — stage 4: cgroup v2 discovery and limit preparation

**Status: draft, resource preparation only. NOT a secure sandbox or a production test executor.**

Package: `internal/cgroupv2`. No extra Go dependencies.

## Why this is a separate increment

The cgroup path returned by `/proc/self/cgroup` identifies the **current** cgroup,
not a guaranteed writable, systemd-delegated subtree. The code correlates
`0::/path` with the `cgroup2` mount reported by `/proc/self/mountinfo`, and
requires the canonical `/sys/fs/cgroup` mount. It rejects incomplete, ambiguous
or unresolvable mounts and unexpected symlink redirection. It does **not** guess
a `user.slice/...` path from the UID.

`CheckDelegation` requires all three controllers (`cpu`, `memory`, `pids`) to
appear in BOTH `cgroup.controllers` and `cgroup.subtree_control` for the parent.
It does **not** change `cgroup.subtree_control` for the caller or reorganize
systemd units: those operations can affect unrelated host workloads.

`Prepare` creates a random-named child under the discovered parent, writes and
reads back `memory.max`, `cpu.max`, and `pids.max` and checks `cgroup.procs`.
It fails closed on permission errors, missing controllers, missing pseudofiles,
or mismatched limit values. `Group.Remove` only works on an empty child and
returns errors; cleanup is not silently treated as successful. A failed setup
makes a best-effort attempt to remove its empty child; caller must also surface
cleanup failures in the future production integration.

| Controller | Example policy | Meaning |
| --- | --- | --- |
| memory.max | 536870912 | 512 MiB aggregate memory budget; failure/OOM subject to kernel semantics |
| cpu.max | 50000 100000 | 50% of one CPU core on average, **throttling**, not elapsed-time kill |
| pids.max | 100 | Counts kernel tasks (including threads), **not** Go goroutines directly |

These policy values are examples, **not** universal defaults; the Go toolchain
can need substantially more resources. Apply independent wall-clock timeouts,
output limits and cleanup policies. cgroups do not isolate filesystem, network,
credentials or syscalls.

## Crucial non-goals and race prevention

**Do not do this:** `cmd.Start(); write PID to cgroup.procs`. A child may fork or
execute untrusted code before its PID is moved. Descendants may remain outside
the resource limits. Stage 4 intentionally exposes **no AttachPID** or runner.

Before coupling it to the executor, implement a privileged, race-free launcher
that places the child in an already configured cgroup **before it can exec**:
for example a reviewed implementation using kernel `clone3(CLONE_INTO_CGROUP)`
with a pinned cgroup FD, or a rigorously verified stopped-child handshake
where no untrusted code can execute before placement. The caller must also
verify the actual child membership and safely handle launch errors, detached
children, termination, `cgroup.kill` and cleanup. PID namespace alone does not
impose cgroup limits. Unsupported kernel or delegation => **refuse execution**.

Do not interpret cgroup presence as evidence of security or correctness of the
agent-produced patch. The current `TxManager.NewManager` still has no trusted
validator and remains unable to authorize a commit.

## How to diagnose the host (read-only)

```sh
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup -o TARGET,FSTYPE,OPTIONS
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```

For a rootless deployment, the administrator/systemd setup must provide a
**dedicated delegated subtree** with `cpu`, `memory` and `pids` controllers and
safe ownership. An arbitrary `user@UID.service` path is not necessarily
writable. Never advise chmod/chown of arbitrary host cgroup files or running
the GoAI service as root merely to bypass failed delegation checks.

## Tests and limitations

- `go test ./internal/cgroupv2` validates parsing, fail-closed handling,
  controller availability and synthetic cgroupfs limit writes.
- A read-only host discovery smoke test does not assume delegation.
- Tests using synthetic filesystem fixtures **are not kernel isolation tests**.
- On non-Linux platforms this module fails explicitly with `ErrUnavailable`.
- This environment exposes a read-only cgroup2 mount and no enabled child
  controllers; **no real cgroup was created or resource-limited process run**.

**Remaining Issue #2 work:** atomic pre-exec cgroup membership, real delegated
Linux test, adversarial memory/process/CPU exhaustion, Bubblewrap integration,
policy-specific auditing, and only then install a privileged validator in the
TxManager. PR chain must remain draft until those checks pass on target hosts.
