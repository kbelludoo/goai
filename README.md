# GoAI MVP — structured, checked edits for Go

**A working experiment, not a new Go compiler or a general-purpose AI agent.**
It uses Go's parser/AST/formatter/typechecker to apply *one kind of operation*,
refuses ambiguous edits, and emits machine-readable JSON diagnostics.

## Requirements

Go 1.23+ (tested using Go 1.23.2), Linux/macOS or Windows with an appropriate shell.
The core program uses only the Go standard library.

## Try it

```sh
go test ./...
go vet ./...
# Demonstrates a failing functional test before correction and a passing test afterwards.
bash scripts/demo.sh
```

Or examine an in-memory edit without touching the file:

```sh
go run ./cmd/goai \
  -file testdata/wallet/wallet.go \
  -patch testdata/wallet/fix.json
```

Add `-write` to commit a validated edit (only after typecheck, **not** tests).
Use version control or a temp copy for real projects.

## Supported patch

```json
{
  "action": "replace_binary_operator",
  "target": {
    "function": "Withdraw",
    "assignment_lhs": "w.Balance"
  },
  "expected_operator": "+",
  "new_operator": "-"
}
```

The engine finds a binary expression *on the right side* of an assignment
in a named function or method. It supports `+`, `-`, `*`, `/`, and requires
exactly **one** matching expression. It then modifies the AST token directly.
The user/agent **cannot** submit raw Go replacement code through this patch.
An optional `expected_file_sha256` guards against editing an unexpected file
revision; `expected_operator` is always required.

### Validation steps

1. Reject malformed and unknown JSON fields.
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
- No generalized AST edit DSL, symbol-aware renaming, or cross-file refactors.
- A name/assignment selector is only a minimal stable target. Method receiver
  names, source semantic IDs, and optimistic locking still need refinement.
- Standard `go/types` messages are wrapped as JSON, not yet explained with
  suggested, machine-checkable repairs.
- Reformatting the file may produce larger diffs than strictly necessary.
- Atomic file replacement is not a cross-process transaction/lock.
- The `reflect`/`unsafe` import ban is a demonstration policy, not an
  objectively optimal rule for all Go applications.

## Exit codes

- `0`: candidate valid (written only with `-write`)
- `1`: invalid arguments or patch
- `2`: AST operation or typecheck rejected
- `3`: write rejected

## Direction

Use an LLM to propose structured operations, compare its success rates against
plain Go text patches on the **same tasks with the same model**. Measure
functional tests, attempts, time and token usage. A compiler alone cannot
establish the agent's reliability.

## Repository and CI

The module path is `github.com/kbelludoo/goai`. A GitHub Actions workflow
runs `go test ./...`, `go vet ./...` and the end-to-end demonstration on pushes
and pull requests. The initial CI run passed on GitHub; future PR runs must still be checked.

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
