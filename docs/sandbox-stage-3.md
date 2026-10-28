# GoAI Issue #2 — Stage 3: detached-process containment canary

**Status: opt-in experimental preflight; no untrusted code execution or trusted validation receipts.** This increment augments the Stage 2 Bubblewrap audit. It does not authorize commits and does not integrate with `TxManager`.

## What gets tested

The trusted static `goai-isolation-probe` starts a second copy of itself with `Setsid=true`, detaching it from its parent's process group. The daemon writes a private readiness marker and intentionally remains alive for a bounded eight seconds. The parent waits for a host-controlled release signal before exiting.

The host uses a fresh 256-bit CSPRNG marker to find the **live daemon's host PID** by reading `/proc/<pid>/cmdline` and to check its `/proc/<pid>/ns/pid` link. It demands **exactly one live daemon in a PID namespace distinct from the host** before releasing the parent. After `bwrap` and the supervisor have exited, it scans again and rejects a surviving daemon. This avoids relying on `ps | grep`, misleading PID values from inside a namespace, or the absence of a sentinel file as evidence of process death.

The process-canary Bubblewrap invocation has `--unshare-all`, `--die-with-parent`, `--new-session`, drops capabilities, and binds only a temporary 0700 **control directory** (read/write) plus the trusted static probe (read-only). It deliberately does not share the source checkout or toolchain. The private control directory is **not** a general-purpose workspace and must not be exposed to arbitrary agent-authored code.

The existing network and mount namespace canaries remain required. **All three canaries now run as part of the same `Auditor.Audit` call**, but the process canary uses a separate short-lived sandbox invocation with an independently restricted mount policy. Before this project can run untrusted code, the exact final execution policy must be verified: an audit of a *similar* command is not a guarantee about a different command.

## How to run on the target Linux host

Install a maintained Bubblewrap build, then run:

```sh
GOAI_BWRAP_INTEGRATION=1 go test -count=1 -v ./internal/sandboxcheck -run TestBubblewrapRealIntegrationOptIn
```

If the host lacks usable user namespaces, Bubblewrap, visible procfs or the requisite mount capabilities, **the test fails closed**. It does not fall back to direct host execution. Require an isolated nonproduction test host for the first run and capture the kernel version, Bubblewrap version and test output for deployment records.

The default local tests include a separate **positive host control** proving that the unique PID scanner sees a real process started by our trusted helper. This host test is **not** a sandbox test. No Bubblewrap binary was installed in the development environment for this increment; consequently the real integration remains unverified here.

## What the canaries *do not* prove

- These are empirical, limited observations, **not cryptographic proof** or mathematical containment guarantees. A daemon that disappears for other reasons does not validate arbitrary namespace configurations, and root/kernel vulnerabilities remain outside this test.
- The current supervisor and process canary do not enforce a memory limit, CPU quota, PID quota, filesystem IO limit, disk quota, syscall profile, or network allowlist for untrusted tests. A hostile process could change arguments, exec a different binary, or attempt kernel exploits; do not assume scanning one trusted marker covers them.
- `RLIMIT_NPROC` counts tasks/processes under credential-dependent Linux semantics; it does **not** constrain Go goroutines or guarantee prevention of fork bombs. `RLIMIT_AS` limits virtual address space, **not RSS/RAM usage**, and may conflict with the Go runtime. `RLIMIT_CPU` is per-process CPU time, not an aggregate cgroup quota.
- True resource protection will require a tested cgroups v2 backend (especially `memory.max`, `pids.max`, `cpu.max`, and cleanup), available to an unprivileged service or managed by a privileged controller. The strict executor must refuse operation if required limits cannot be installed.
- The draft AtomicWriter still has a race window against noncooperating external writers. Any `flock`-style coordination is advisory and not a kernel content-based compare-and-swap.
- The single-run canaries do not replace an authenticated, protected validator, immutable candidate-bound evidence, and a reviewed production runtime policy.

**Merge policy:** keep PRs draft and `TxManager` fail-closed until a complete test executor with isolation, resource quotas, and evidence binding passes real adversarial integration on every supported deployment target.
