# GoAI — a Go edit protocol written for programs, usable by humans

**A working experiment, not a new Go compiler or a general-purpose AI agent.**
It uses Go's parser/AST/formatter/typechecker to apply *one kind of operation*,
refuses ambiguous edits in a way a caller can retry, and emits a versioned JSON
envelope instead of prose.

The design argument behind it lives in
[docs/design-for-agents.md](docs/design-for-agents.md): Go's canonical syntax,
fast toolchain and static types already make it unusually machine-friendly; what
is missing is the *interface* — stable identifiers, resumable refusals, and
compact context.

## Requirements

Go 1.23+ (tested using Go 1.23.2), Linux/macOS or Windows with an appropriate shell.
The core program uses only the Go standard library.

## Try it

```sh
go test ./...
go vet ./...
# Reconnaissance, then a resumable refusal, then a validated write and a test.
bash scripts/demo.sh
```

Three modes, each printing exactly one JSON object on stdout:

```sh
# 1. Context: identifiers + editable sites for one file, not the file body.
go run ./cmd/goai context -file testdata/wallet/wallet.go
go run ./cmd/goai context -file testdata/wallet/wallet.go -brief -typecheck

# 2. Check: parse + type-check only, no edit.
go run ./cmd/goai check -file testdata/wallet/wallet.go

# 3. Patch: validate an operation in memory; add -write to replace the file.
go run ./cmd/goai patch -file testdata/wallet/wallet.go -patch testdata/wallet/fix.json
```

The pre-0.2 invocation (`goai -file f.go -patch p.json`, no mode) still works.

## Supported patch

```json
{
  "action": "replace_binary_operator",
  "target": {
    "symbol": "wallet.(*Wallet).Withdraw",
    "assignment_lhs": "w.Balance"
  },
  "expected_operator": "+",
  "new_operator": "-"
}
```

The engine finds a binary expression *on the right side* of an assignment in the
selected function. It supports `+`, `-`, `*`, `/` and requires exactly **one**
matching expression. It then modifies the AST token directly. The caller
**cannot** submit raw Go replacement code through this patch.

### Target selectors

| Field | Meaning |
| --- | --- |
| `symbol` | Stable identifier from `goai context`: `pkg.F`, `pkg.(*T).M`, `(T).M` (package prefix optional). |
| `function` | Bare function/method name (syntactic, pre-0.2 style). Mutually exclusive with `symbol`. |
| `receiver` | Receiver type as written: `*Wallet`, `Wallet`, `*List[T]`. Narrows duplicate method names. |
| `assignment_lhs` | Required. Left-hand side of the assignment, formatted. |
| `occurrence` | Optional, 1-based in source order. Selects one site when several still match. |

An optional `expected_file_sha256` guards against editing an unexpected file
revision; `expected_operator` is always required.

### When it refuses

Every diagnostic carries `code`, `message`, `hint`, `retryable` and, where
relevant, a located position. Ambiguity and precondition failures also return
`candidates`: each candidate is a complete `retry_target` that can be sent back
as `target`, so a refusal never dead-ends a loop.

Abridged (`file`, `line`, `column` and the untruncated hint are also present):

```json
{
  "code": "GOAI-AMBIGUOUS-001",
  "message": "target matched 2 binary expressions; no edit was made",
  "hint": "retry with target.occurrence (or send a candidate's retry_target) ...",
  "retryable": true,
  "candidates": [
    { "symbol": "amb.Total", "assignment_lhs": "x", "operator": "+",
      "line": 4, "column": 7, "occurrence": 1,
      "retry_target": { "symbol": "amb.Total", "assignment_lhs": "x", "occurrence": 1 } }
  ]
}
```

Successful results list the steps the tool deliberately did **not** take:
`apply_write` (validation was in memory) and `verify_with_tests`
(type-checking is not behaviour).

### Validation steps

1. Reject malformed and unknown JSON fields, conflicting selectors, `occurrence < 1`.
2. Check an optional file-content hash and mandatory operator precondition.
3. Parse the original Go file and resolve a unique target; reject ambiguity.
4. Modify a syntax-tree operator in memory and format it.
5. Re-parse the generated Go file.
6. Reject forbidden imports `reflect` and `unsafe` (illustrative fixed policy).
7. Type-check non-test files in the same directory using `go/types`.
8. Return JSON with updated candidate source and diagnostic codes.
9. Only on explicit `-write`, confirm file content hash again and atomically
   replace the file with the candidate. This does **not** run tests.

### Important limitations

- Successful parsing/type-checking **does not mean logical correctness**.
  The demonstration uses a functional unit test to catch the original logic
  error. Future versions should support validating candidate patches in a
  temporary workspace before writing to the original.
- No module-aware type-checking of third-party imports yet. Packages relying
  on external dependencies may be rejected by the limited standard-library
  importer. Build tags, generated code, and cgo are not supported.
- Identifiers are file-scoped and syntactic: `pkg.(*T).M` is stable within a
  file revision, but there is no module-wide symbol table, so cross-package
  name collisions and generic receiver forms are not canonicalized.
- No generalized AST edit DSL, symbol-aware renaming, or cross-file refactors.
- Standard `go/types` messages are wrapped with a hint, not translated into a
  suggested, machine-checkable repair.
- Reformatting the file may produce larger diffs than strictly necessary.
- Atomic file replacement is not a cross-process transaction/lock.
- The `reflect`/`unsafe` import ban is a demonstration policy, not an
  objectively optimal rule for all Go applications. Hard-coding taste into a
  tool is the one failure mode this repository warns about most.

## Exit codes

- `0`: valid candidate / clean check (written only with `-write`)
- `1`: invalid arguments, patch, or I/O
- `2`: AST operation, ambiguity, or typecheck rejected
- `3`: write rejected

## Direction

Use an LLM to propose structured operations, compare its success rates against
plain Go text patches on the **same tasks with the same model**. Measure
functional tests, attempts, time and token usage. A compiler alone cannot
establish the agent's reliability. See
[docs/benchmark.md](docs/benchmark.md) for the protocol and
[docs/design-for-agents.md](docs/design-for-agents.md) for the roadmap.

## Repository and CI

The module path is `github.com/kbelludoo/goai`. A GitHub Actions workflow
runs `go test ./...`, `go vet ./...` and the end-to-end demonstration on pushes
and pull requests. CI includes `go test`, `go test -race`, `go vet` and the
end-to-end demo; runs are green on GitHub Actions (check each PR individually).

## License

No license has been selected yet. Choose an open-source license deliberately
before encouraging external redistribution.


## GoAI 0.2 protocol draft (experimental)

See [the 0.2 architecture RFC](docs/architecture-0.2.md) for a proposed
transaction lifecycle and recognition protocol. The new `internal/agentproto`
and `internal/recon` packages implement **data contracts, guard checks and
read-only candidate discovery**. They are not wired into the GoAI CLI.

The draft does **not** provide a secure test sandbox, trusted validation
attestations, durable transaction commits, or improved success/token benchmarks.
Track implementation in [transactions](https://github.com/kbelludoo/goai/issues/1),
[sandbox](https://github.com/kbelludoo/goai/issues/2), and
[recognition](https://github.com/kbelludoo/goai/issues/3).

### Candidate-integrity hardening (draft PR)

The 0.2 draft now supports a **sealed in-process candidate catalogue** and
compact agent-facing summaries. `recon.Discover` returns a local registry;
serialize `registry.Response()` to an agent, then accept only its candidate
**ID** and resolve it back against that original registry. The digest binds
the transaction, source revision, entire patch and expected output revision.

`ValidationReport` structurally binds the intended candidate and checks the
required gate names, but **reports are not authentic evidence**. No validator,
sandbox, durable authoritative state or safe commit protocol has been added.
Do not use any exported `Transaction.State` value as authorization for changes
written by an untrusted client. The 0.1 CLI still provides its original
manual `-write` behavior, which has *not* gained sandbox validation.

## Private transaction manager (0.2 draft)

`internal/txmanager` now contains an **in-process fail-closed state-machine
prototype** with CSPRNG opaque capabilities, a sealed candidate catalogue,
whole-file locks, version checks, one-time commit capabilities and process-local
hash-chained audit events. Candidate discovery and slow validation now run
outside the global mutex, while whole-file reservations remain active until
commit or rejection (see concurrency tests and [the transaction RFC](docs/txmanager-0.2.md)).
The public `NewManager` intentionally has **no
privileged validator**, so it **cannot approve or commit** user code. Tests
exercise the positive path only with a synthetic *in-package* validator.
The project has **no secure sandbox** or durable transaction manager yet.
See [transaction manager design](docs/txmanager-0.2.md) for guarantees and
limitations.

### Revision-checked cooperative commit (Linux, design increment)

The transaction manager's single-file write path now uses
`internal/atomicwriter` to stage a replacement, acquire a persistent Linux
`flock` sidecar, check original content and inode identity, and atomically
rename on a matching revision. This **does not** create kernel-level CAS,
securely isolate paths, stop non-cooperating IDE/Git writes, or make the sandbox
available. See [writer limitations](docs/atomicwriter-0.2.md).


### Issue #2 stage 1: trusted-process supervisor (not a sandbox)

`internal/supervisor` provides a Linux-only best-effort process-group
termination helper for **trusted internal commands**, with cancellation and
bounded in-memory diagnostics. Integration tests cover canceling a process
with descendants and normal parent exit with a still-running child. This is
**not** permitted to execute AI-generated code: no network, filesystem,
credential, syscall or resource isolation is implemented. The TxManager
remains fail-closed without a validated sandbox. See
[the stage 1 security scope](docs/sandbox-stage-1.md).

### Issue #2 stage 2: controlled host canaries (non-authorizing)

`internal/sandboxcheck` runs a **trusted, static helper** under Bubblewrap with
separate Linux PID, network and mount namespaces. It verifies both controlled
host resources (a loopback HTTP server and an ephemeral `/tmp` sentinel) and
namespace identity, failing closed if `bwrap` cannot start or a canary detects
host access. The helper never runs agent code, and this preflight is not yet
part of a production sandbox validator; `TxManager` **still cannot approve**.
On platforms without `bwrap` this stage cannot be validated end-to-end. See
[stage 2 threat model and opt-in test](docs/sandbox-stage-2.md).


## GoAI sandbox stage 3: detached-process canary

`internal/sandboxcheck` additionally tests the cleanup of a trusted `setsid`
process inside a Bubblewrap PID namespace. It uses a host-visible, nonce-bound
`/proc` scanner with a *positive live-daemon control* before termination.
See [the stage-3 design](docs/sandbox-stage-3.md). The real isolation test is
opt-in; neither these canaries nor `CGO_ENABLED=0` prove a safe untrusted
executor. The public transaction manager still cannot authorize commits.

## Issue #2 stage 4: fail-closed cgroup v2 discovery (not an executor)

`internal/cgroupv2` locates the running process's cgroup v2 membership using
`/proc/self/cgroup` and `/proc/self/mountinfo`, verifies resource-controller
**delegation**, and can prepare an empty child with verified CPU, memory and
PID limits. It cannot yet launch or attach untrusted processes: attaching a
running `bwrap` by PID is racy and expressly forbidden until a trusted pre-exec
placement mechanism is implemented. See [stage 4 design](docs/sandbox-stage-4.md).

## Issue #2 stage 5: atomic pre-exec placement and a host policy gate

`internal/cgroupv2` now takes an **explicit delegation root** (never the current
cgroup, which is usually an undelegable `init.scope`), enables the three required
controllers only on a process-free root, and launches children with
`clone3(CLONE_INTO_CGROUP)` — placement happens in the kernel *before* exec, so
there is no fork-then-move window. Membership is verified, termination uses
`cgroup.kill`, and every refusal is a named error.

`internal/sandboxpolicy` is the fail-closed gate:

```sh
go run ./cmd/goai sandbox -limits default            # read-only verdict, exit 2 when denied
go run ./cmd/goai sandbox -root <delegated> -enable  # explicit host mutation
go run ./cmd/goai sandbox -root <delegated> -limits 512MiB/50%/100 -probe /usr/bin/true
```

An `unknown` check denies: "not verified" must never serialize as allowed. A
process that may write the delegation root can still move itself out of the
budget, so prevention requires UID separation in the sandbox; `VerifyContains`
detects it, and this is why `TxManager` still has no validator. See
[stage 5 design](docs/sandbox-stage-5.md).
