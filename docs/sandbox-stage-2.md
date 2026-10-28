# GoAI Issue #2 — Stage 2: controlled canaries and Bubblewrap preflight

**Status:** non-authorizing, opt-in isolation preflight only. The `TxManager`
remains unable to approve untrusted code. No agent-authored tests run here.

## What this increment does

1. Builds a **trusted, statically linked** `goai-isolation-probe` helper outside
   the sandbox (use `CGO_ENABLED=0 go build -o /safe/location/goai-probe
   ./cmd/goai-isolation-probe`). Keep its binary and containing directories
   under trusted control, not in a writable agent workspace.
2. The host creates an `httptest.NewServer` on loopback and a unique, readable
   host sentinel inside `/tmp`. The host first **positively checks** that it
   can reach the endpoint and read the sentinel.
3. It launches **only the trusted helper** under `bwrap --unshare-all
   --die-with-parent --new-session`, with a private `/tmp`, `/proc`, `/dev`,
   and read-only bind of the static helper. It does **not** bind the host's
   `/usr`, `/home`, project, Go toolchain, module cache, or `/tmp`.
4. The helper attempts those same host-only resources and reports its kernel
   namespace IDs (`net`, `mnt`, `pid`) read through `/proc/self/ns/*`.
5. The host requires three namespace IDs to differ from its own and refuses
   success if *either* controlled resource is accessible, or the response is
   invalid, missing, duplicated, or truncated. Errors quarantine the auditor
   instance. Disabled user namespaces, missing `bwrap`, or unsupported kernels
   **fail closed**, with no downgrade to host execution.

## Verification

Default CI tests assess fail-closed behavior and detection logic; on the host,
the positive controls are tested against reachable resources.

Opt-in **real** integration on a Linux machine with working Bubblewrap and
user namespaces:

```sh
GOAI_BWRAP_INTEGRATION=1 go test -v ./internal/sandboxcheck -run TestBubblewrapRealIntegrationOptIn
```

**This environment has no `bwrap` installed; no actual kernel-isolation run
was completed during development.** Default `go test` passing MUST NOT be
reported as proof of sandbox isolation. Use the opt-in test and capture its
output on each supported deployment image.

## Remaining security work

- Actual untrusted-code executor with audited rootfs/workspace/module cache,
  non-writable host mounts, and a secure immutable toolchain/probe distribution.
- Enforced CPU, memory, pids, disk/output, wall-clock and job termination
  limits; detection of escapes from process groups; independent PID-namespace
  tests and correct cleanup on daemonization and cancellation.
- Credential, UID/GID, secret, syscall, cgroup and permission policy.
- Trusted, candidate-bound validation receipts and private wiring into
  `TxManager`; no arbitrary command lines or paths accepted from an agent.
- Linux kernel/bwrap vulnerabilities and escape routes require separate
  threat modeling; **canaries do not constitute a mathematical guarantee**.
- The current auditor only checks two resources and namespace identity. A
  successful probe does not mean the future test runner has an identical
  filesystem/mount policy or safely executes arbitrary code.

The supervisor remains a best-effort process group cleaner, not an isolation
boundary. Never enable an unsafe fallback in production.
