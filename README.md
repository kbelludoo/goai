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
and pull requests. **The workflow has not been verified on GitHub yet.**

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
