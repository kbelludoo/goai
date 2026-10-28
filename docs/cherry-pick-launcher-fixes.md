# Launcher fixes: what each commit changes and how to verify it

Six commits on this branch are deltas against
`feature/goai-cgroup-self-migration-stage5` (PR #10). Cherry-pick them in order;
each one leaves the tree buildable and adds its own regression tests.

```sh
git log --oneline --reverse origin/pr10..origin/arena/5c4bdb6c-goai
```

| # | Commit subject | Priority | File(s) | Regression test |
| --- | --- | --- | --- | --- |
| 0 | import the self-migration launcher verbatim | prerequisite | launcher, `cmd/goai-cgroup-exec`, probe, opt-in test | (none: verbatim from PR #10) |
| 1 | unique `GOAI-CGROUP-02x` codes | P1 | `launcher_linux.go` | `TestLauncherCodesDoNotCollideWithDelegationErrors` |
| 2 | exclusive, caller-owned, childless cgroup | P0 | `launcher_linux.go` | `launcher_exclusive_linux_test.go` |
| 3 | scrub inherited descriptors | P0 | `launcher_linux.go` | `launcher_fds_linux_test.go` |
| 4 | exec the validated inode (`execveat`) | P1 | `launcher_linux.go`, `exec_linux.go` | `exec_linux_test.go` |
| 5 | accept a target with no extra argv | P2 | `cmd/goai-cgroup-exec` | `cmd/goai-cgroup-exec/main_linux_test.go` |
| 6 | supervisor-authorized ticket | blocking | `authority_linux.go`, launcher, CLI | `authority_linux_test.go`, CLI tests |

## Why commit 2 is more than an emptiness check

`cgroup.procs` empty is a snapshot. Commit 2 makes it a property from two
directions:

- **identity**: the descriptor (not the path) must be a real cgroup2 directory,
  owned by the caller, with no group or other write permission — so nobody else
  can add members or children later;
- **state**: no pre-existing tasks and no child cgroups, checked through
  `openat` on that descriptor;
- **after the join**: the group must contain exactly the joiner, which detects a
  process that entered between the check and the write.

That last check is what makes the opt-in probe's `PASS` meaningful: with a
co-tenant in the group, `pids.events:max` can increment for reasons unrelated to
the probe.

## Why commit 6 is not documentation

`execPrepared` is unexported. The only production entry point is
`Ticket.Exec`, and a `Ticket` can only be produced by
`Authority.Authorize`, which requires a `Peer` read from the kernel via
`SO_PEERCRED`. Concretely, this request is refused even when the paths are
well-formed:

```json
{"cgroup_path": "/sys/fs/cgroup/delegated/x", "target_path": "/bin/sh", "argv": ["/bin/sh"]}
```

if the caller's UID is not in `requester_uids`, or if `/bin/sh` is outside
`target_dirs`. The failure is `GOAI-CGROUP-025`/`-026`, exit 125/126, and no
process is started.

## Evidence criteria for the resource canaries

Two canaries need better acceptance rules than "the counter changed", because a
single counter can be absent or sampled late:

| canary | primary signal | corroboration | failure that must be loud |
| --- | --- | --- | --- |
| memory (`memory.max`) | `memory.events:oom_kill` increments | payload did **not** exit 0, and `memory.peak` is within 90% of the cap | payload survived the cap |
| CPU (`cpu.max`) | `cpu.stat:nr_throttled` or `throttled_usec` increments | `cpu.stat:usage_usec` well below wall time | busy loop consumed a full core |
| pids (`pids.max`) | `pids.events:max` increments | launcher probe counts refusals, not only successes | probe reports success without denials |

An OOM does not always produce `oom_kill` in every kernel configuration (a
`memory.high` policy throttles instead; a global OOM may pick another victim),
and throttling depends on the observation window, so each canary accepts a small
set of signals and still fails if *none* appear. All of them run only on a
delegated host; see `docs/sandbox-stage-5.md`.

## Reproducing `-race`

`go test -race ./...` is part of the CI workflow on PR #10's branch but not on
this branch's (the workflow file cannot be edited with the token used here). Run
it locally, or rely on PR #10's CI after cherry-picking:

```sh
go test -race ./internal/cgroupv2 ./cmd/goai-cgroup-exec
```
