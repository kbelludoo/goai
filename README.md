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
and pull requests. **The workflow has not been verified on GitHub yet.**

## License

No license has been selected yet. Choose an open-source license deliberately
before encouraging external redistribution.
