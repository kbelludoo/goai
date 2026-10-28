# GoAI sandbox Issue #2 — stage 5: atomic pre-exec placement and a host policy gate

**Status: draft. Prepares and places processes under cgroup limits; still NOT a
validated untrusted-code executor.**

Packages: `internal/cgroupv2` (extended), `internal/sandboxpolicy` (new).
No extra Go dependencies.

## What stage 4 left open, and why it could not be fixed in place

Stage 4 discovers the *current* cgroup and prepares an empty child under it. Two
problems follow from that choice:

1. **The current cgroup is usually not delegable.** Under systemd a service's
   processes live in `<unit>/init.scope`. That leaf cannot hand controllers to
   children, so `CheckDelegation` fails forever — a valid service gets permanent
   quarantine with no way to explain itself.
2. **Controller delegation must be enabled one level up, and only on a
   process-free cgroup.** Writing `+memory` into the `cgroup.subtree_control` of
   a cgroup that holds tasks either returns `EBUSY` (controller available) or
   attaches nothing (`-EBUSY` semantics differ per controller). Enabling it on a
   cgroup that also runs unrelated workloads changes their confinement.

Measured on the machine used to write this stage (a container, kernel 6.1):

```
$ cat /proc/self/cgroup
0::/user
$ cat /sys/fs/cgroup/init.scope/cgroup.subtree_control     # empty
$ cat /sys/fs/cgroup/init.scope/cgroup.procs               # 1, 167 -> holds tasks
$ mkdir /sys/fs/cgroup/probe
mkdir: cannot create directory '/sys/fs/cgroup/probe': Permission denied
```

So stage 5 replaces "guess the current cgroup" with an **explicit delegation
root** that an administrator names, and refuses to guess. That is not a
convenience change: guessing produced both false negatives (quarantined forever)
and a false positive risk (enabling controllers on a busy cgroup).

## The race stage 4 correctly refused to close with a PID write

`cmd.Start(); write(pid, cgroup.procs)` is unsafe: between `fork` and the write,
the child may already be executing untrusted code, and descendants created in
that window stay outside the budget. `Handle.Start` closes the window in the
kernel instead:

```go
inherited.UseCgroupFD = true
inherited.CgroupFD = int(handle.dir.Fd())   // O_DIRECTORY|O_CLOEXEC fd
cmd.Start()                                 // -> clone3(CLONE_INTO_CGROUP)
```

Four properties make this a check rather than a hope:

- **The kernel places the child before it runs.** `clone3` creates the task
  directly in the target cgroup, so there is no fork-then-move window at all.
- **The fd is the anchor.** It is opened once on the freshly created cgroup with
  `O_DIRECTORY|O_CLOEXEC`, so a later path rename cannot retarget it and the
  child never inherits it.
- **No silent downgrade.** `crypto/syscall`-level details aside, Go's runtime
  builds a `clone3` call only when `UseCgroupFD` is set, and reports the syscall
  error verbatim. There is no fallback path that would start the child unlimited;
  `ErrCloneIntoUnavailable` (ENOSYS/EINVAL/EACCES/EPERM/EBADF/ENOENT) is returned
  and nothing runs.
- **Membership is verified.** `VerifyContains(pid)` requires the cgroup to hold
  exactly the child. Anything else kills the child and returns
  `ErrPlacementUnverified`. An empty cgroup is *not* treated as success, because
  nothing was then observed inside the budget.

Termination uses `cgroup.kill` (Linux 5.14+), which is atomic with respect to
fork: a task cannot escape by racing the write. Kernels without it return
`ErrUnavailable` rather than pretending everything was killed.

## The escape this cannot prevent (and does not claim to)

A process that may write the **delegation root's** `cgroup.procs` can move itself
out of the child cgroup, and cgroup v2 has no per-process opt-out. `Handle`
therefore provides:

- `VerifyContains(pid)` — call before approving a candidate, not only after start;
- `ErrEscaped` — the named failure for a process that is no longer a member.

**Prevention is a UID property, not a cgroup property:** the confined process must
run as a different UID than the GoAI service (for example Bubblewrap with an
unshared user namespace mapping the payload to `nobody`). This is why stage 5 is
still not wired to `TxManager`: `NewManager` continues to have no trusted
validator, and nothing here can approve a commit.

## Fail-closed policy gate

`internal/sandboxpolicy` answers one question — *may this host run untrusted code
under the required controls?* — as JSON, with tri-state checks:

| check | denies when |
| --- | --- |
| `cgroup2_mount` | no cgroup2 in mountinfo/cgroup |
| `limits` | budget missing, below kernel minimums, or `max` |
| `delegation_root` | unset, not on the cgroup2 mount, symlinked, unwritable |
| `process_free_root` | the root holds tasks |
| `controllers_delegated` | `cpu`, `memory`, `pids` not all enabled for children |
| `bubblewrap` | `bwrap` absent — cgroups limit but do not isolate |
| `atomic_placement` | `unknown` until proven by a trusted-binary probe |

`unknown` denies. That is the whole point: a check that could not be performed is
not evidence, and "we did not verify" must never serialize as `"allowed": true`.

```sh
$ go run ./cmd/goai sandbox -limits default
{
  "protocol": "goai/0.2",
  "mode": "sandbox",
  "allowed": false,
  "checks": [ ... {"name": "delegation_root", "status": "fail", "code": "GOAI-CGROUP-004", ...} ],
  "reasons": ["GOAI-CGROUP-004: no delegation root configured; ...", ...]
}
$ echo $?
2
```

Two explicit mutations exist, and neither is a default:

- `-enable` — enable exactly `cpu`, `memory` and `pids` on a **process-free**
  delegated root (`GOAI-CGROUP-005` otherwise). Nothing is chowned or chmodded.
- `-probe /usr/bin/true` — prepare a throwaway cgroup, start one **trusted**
  binary through `clone3`, verify membership, `cgroup.kill`, wait for empty,
  destroy. Only the named binary runs; agent output is never executed.

## Limits are policy, not defaults

`-limits 512MiB/50%/100` means 512 MiB aggregate, 50% of one core on average
(`cpu.max` is **throttling**, not an elapsed-time kill), and 100 kernel tasks
(threads count; goroutines do not map 1:1). `-limits default` is
512 MiB / 50% / 100 and must be asked for explicitly. An empty profile is an
error, because a forgotten budget and an unlimited budget look identical at
runtime.

Even with all of this, cgroups do not isolate the filesystem, the network,
credentials or syscalls. Limits bound damage; they are not a security boundary.

## Tests: what each one actually proves

| Test | Proves |
| --- | --- |
| `root_linux_test.go` synthetic roots | refusals do not mutate the host, missing controllers are named, `at` rejects symlinks/outside paths |
| `TestStartRefusesPreconfiguredPlacement` | caller-provided `UseCgroupFD` is rejected, never silently overridden |
| `TestRandomNameIsUniqueAndOpaque` | child names are unguessable, so a pre-created directory cannot be targeted |
| `policy_test.go` | tri-state gate: unknown denies, empty/unlimited profiles deny, untrusted roots deny |
| `TestRealAtomicPlacementAndLimits` (opt-in) | **kernel behaviour**: `clone3` placement, `memory.max`/`cpu.max`/`pids.max` values, `cgroup.kill` drain |

The opt-in test never runs silently in CI:

```sh
# administrator creates a delegated, process-free root, e.g. a transient unit
GOAI_TEST_CGROUP_ROOT=/sys/fs/cgroup/<delegated> \
  go test ./internal/cgroupv2 -run Real -v
```

Without the variable it skips with that exact instruction. On the machine this
stage was written on it **skipped**, because creating a cgroup requires
privileges the sandbox does not have; the synthetic tests are the only ones that
ran here and they are not kernel tests.

## Remaining Issue #2 work

1. Real delegated Linux host run of `TestRealAtomicPlacementAndLimits`.
2. Adversarial resource tests: fork bomb (`pids.max`), memory exhaustion
   (`memory.max` + OOM behaviour), CPU throttling measurement.
3. Bubblewrap integration that passes `Handle.Start` attrs (namespaces,
   `--uid`/`--gid` to a different UID, which is what actually prevents the escape
   above), plus verifying `bwrap` did not silently weaken flags.
4. Bind the policy gate to the validator install path so `TxManager` can only get
   a validator when `Decision.Allowed` and a fresh probe both hold.
5. Durable audit anchoring for the deny/allow decision itself.
