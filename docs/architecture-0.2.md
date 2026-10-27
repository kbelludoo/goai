# GoAI 0.2: transactional agent interface — draft RFC

**Status: design prototype, NOT a completed transactional editing engine.**

The v0.1 CLI and mutation engine are unchanged by this PR. New packages are
`internal/agentproto` (JSON contracts, lifecycle/gates) and `internal/recon`
(a read-only recognizer that proposes existing engine-supported `+`/`-` edits).

## Contract

1. `RecognitionRequest` binds a `tx_id`, restricted `Intent`, `SemanticSelector`
   and *exact full-file SHA-256 revision*. Selectors use the `exactly_one` policy.
2. `recon.Discover` parses the source and enumerates **bounded, mechanically
   generated candidates**, cross-checking each with `engine.Apply` to avoid
   proposing an unsupported or ambiguous patch. No user-code execution.
3. `RecognitionResponse` supplies version-scoped candidate IDs, explicit patches,
   and structured diagnostics. `Choose` refuses stale IDs or duplicate matches.
4. The `Transaction` draft moves `pending -> proposed` only with a selected
   candidate, and `proposed -> validated` only via `MarkValidated` after an
   explicit report of successful syntax, type, vet, build and test gates.
   Contracts are required when postconditions are specified. `RequirePass`
   refuses absent, duplicate, skipped or failing required gates. A future
   executor must produce **trusted** reports and enforce commit preconditions.
5. These types are **not attestations**. Nothing in this PR executes tests,
   writes files, implements secure isolation, or commits to Git. A future trusted
   executor must generate evidence, enforce optimistic locking at commit, and
   prevent untrusted agents from forging validation/transaction state.

## JSON request example

```json
{
  "tx_id": "tx-wallet-01",
  "selector": {
    "file": "wallet.go",
    "declaration": "Withdraw",
    "assignment_lhs": "w.Balance",
    "file_sha256": "<64 hex digits from the real file>",
    "match_policy": "exactly_one"
  },
  "intent": {
    "kind": "fix_arithmetic_logic",
    "description": "Withdrawing an amount should decrease the balance"
  },
  "max_candidates": 8
}
```

A **description is an untrusted hint, not a proof of correctness**. Today the
recognizer only offers the mechanically plausible `+` ↔ `-` candidate; the
agent selects one, and a later validator must test it. No guaranteed 90% token
savings, zero regressions, or universal correctness is claimed.

## Version identity and semantics

- The symbol path identifies the *semantic neighborhood*. Its role is stable
  only to the degree maintained by the codebase; name reuse and refactoring
  require re-resolution.
- The source hash is a snapshot precondition, **not** an enduring node ID.
- Candidate IDs are deliberately version-scoped: after any file change the
  recognizer must be rerun; IDs are not portable to the new revision.
- Existing `engine.Apply` only understands unqualified function names; method
  receiver-qualified selectors are explicitly rejected until supported.
- An ambiguous engine mutation is excluded from actionable candidates, not
  quietly applied to the first occurrence.

## Next implementation increments

1. Transaction manager using trusted, immutable stored states and compare-and-
   swap on source revision when committing. Durability and crash recovery need
   explicit tests (the current `WriteAtomic` is **not** a multi-file transaction).
2. True isolated test executor. Temp folders, Go `context` timeouts, and process
   killing **do not** by themselves isolate filesystem, network or child
   processes. Pick/test a sandbox backend with explicit platform capabilities;
   fail closed if security requirements cannot be enforced. Do not claim
   namespaces, cgroups, tmpfs or read-only mounts are available everywhere.
3. Module-aware overlays for whole-package analysis (e.g. `go/packages`); no
   claim that `go/types` alone supports memory overlays for arbitrary modules.
4. Receiver-qualified symbol resolution, typed AST operations and structured
   test diagnostics. Do not encode arbitrary executable contracts or shell
   strings in agent-provided JSON.
5. Paired four-arm benchmark: Go/text; Go/text+JSON feedback;
   AST operations; high-level intent/catalog. Same model and budget, hidden
   holdout tests, tokens for **all** tool responses, confidence intervals.

## Explicit non-goals of this PR

No permission model; no secure sandbox; no AI provider adapter; no automatic
mutation application; no CI benchmark claims; no API key handling. This is a
small standard-library design increment that can be reviewed and extended.
