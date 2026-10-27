# GoAI 0.2: transactional agent interface — draft RFC

**Status: design prototype, NOT a completed transactional editing engine.**

The v0.1 CLI and mutation engine are unchanged by this PR. New packages are
`internal/agentproto` (JSON contracts, lifecycle/gates) and `internal/recon`
(a read-only recognizer that proposes existing engine-supported `+`/`-` edits).

## Contract (revision-bound, lazy catalogue)

1. `RecognitionRequest` binds a transaction ID, intent, exact normalized source
   path, declaration, selector and SHA-256 revision. Ambiguous edits are not
   actionable. Receiver-qualified symbols are not yet supported.
2. `recon.Discover` runs the existing `engine.Apply` **preflight** for each
   syntactically supported mutation. It returns a `CandidateCatalog`, held only
   by trusted in-process code. After discovery, `Seal` freezes its registry;
   the recognizer never executes untrusted tests.
3. An agent receives **only** `catalog.Response()`: summary, opaque candidate ID,
   digest, source revision, output digest, diagnostics and `capped` flag.
   Crucially, **no raw AST patch is included in this response**.
4. When the agent selects an ID, `Transaction.SelectCandidate(catalog, id)`
   resolves it from that sealed local registry. It refuses unknown IDs and
   stale file hashes. The trusted engine can use `catalog.Resolve` to obtain
   the full patch; client-supplied `Candidate` objects must never authorize it.
5. `MarkValidated` requires that the structural report identify the exact
   transaction, candidate ID/digest, original revision, expected output digest,
   required gates and validation policy hash. This **does not authenticate**
   the report or execute any checks. Calling it with client-generated JSON
   remains unsafe. The `Validated` state is advisory until a trusted validator
   and private authoritative transaction manager exist.
6. No code in this PR commits files or attests that the tests really ran.
   Implementing trusted execution, provenance, immutable authoritative state
   and compare-and-swap commits belongs to the next increments.

## Lazy catalogue response example

```json
{
  "tx_id": "tx-wallet-01",
  "source_sha256": "<snapshot SHA-256>",
  "candidates": [{
    "id": "mut_<canonical candidate digest>",
    "tx_id": "tx-wallet-01",
    "source_sha256": "<snapshot SHA-256>",
    "digest": "<SHA-256 of transaction, revision, full patch, output>",
    "output_sha256": "<expected output SHA-256>",
    "summary": "Change + to - in assignment to w.Balance"
  }]
}
```

Only an ID needs to return over the agent protocol. A future production executor
must re-resolve/recheck the revision and must not accept user-supplied patches,
validation statuses or candidate registries as trusted authority.

## JSON request example

```json
{
  "tx_id": "tx-wallet-01",
  "selector": {
    "file": "/absolute/path/to/wallet.go",
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
- Candidate IDs are derived from a canonical digest of the transaction ID,
  exact patch, original revision and preflight output hash. After any file
  change the recognizer must be rerun. The sealed catalogue rejects late
  registration; returned response summaries are detached value copies.
- Current selectors require the exact normalized source path; repository-root
  mapping and safe realpath/symlink handling remain future work.
- Existing `engine.Apply` only understands unqualified function names; method
  receiver-qualified selectors are explicitly rejected until supported.
- An ambiguous engine mutation is excluded from actionable candidates, not
  quietly applied to the first occurrence.

## Next implementation increments

1. Authoritative transaction manager with private states and trusted validation
   attestation. The exported `Transaction` is still only a draft DTO; code
   executing untrusted agent messages must **not** treat its `State` as an
   authorization decision. Follow with compare-and-
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
