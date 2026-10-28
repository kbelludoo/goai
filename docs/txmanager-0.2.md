# GoAI 0.2 — private transaction manager (incremental RFC)

This PR increment adds `internal/txmanager`, **not** a finished autonomous coding
executor. It is designed to fail closed until a separate trusted sandbox
validator is implemented and integrated by privileged GoAI code.

## Trust boundary and API

```go
manager, _ := txmanager.NewManager(time.Minute)
menu, _ := manager.Begin(recognitionRequest)            // read-only discovery
_, _ = manager.Choose(menu.TransactionID, menu.ReconToken, candidateID)
_, err := manager.Validate(ctx, menu.TransactionID, menu.ReconToken)
// err == txmanager.ErrValidatorUnavailable, by design.
// A production instance cannot obtain a CommitToken or Commit from this API yet.
```

- The manager privately owns transactions, sealed catalogues, file locks,
  source hashes, candidate output and commit capabilities. No agent receives
  internal structs, AST patches or a mutable validation status.
- `Begin` returns only compact, revision-bound candidate summaries and a
  256-bit CSPRNG bearer `ReconToken`. `Choose` accepts only its issued token and
  candidate ID. It never accepts client-supplied patches.
- `Validate` rechecks the exact source revision and selected candidate output.
  **The public `NewManager` has no validator**: it rejects all approvals with
  `ErrValidatorUnavailable`. Only private package tests use a synthetic stub
  to exercise approval, failure and commit paths. A stub passing is never
  evidence of actual sandbox execution or logical correctness.
- With a genuine installed validator, successful validation would issue a
  separate one-time 256-bit bearer `CommitToken`. `Commit` checks expiry,
  expected state, token, original file version and candidate output digest.
  The capability is consumed on a commit attempt. A forged JSON `{status:
  "pass"}` has no effect on authoritative state.
- File locks are intentionally **whole-file**, not semantic/symbol locks;
  this is conservative because the current edit pipeline formats the whole
  file. A map reservation implements this without blocking a scope mutex while
  holding the global mutex: conflicting requests return `ErrLocked` immediately.
- `Begin` now reserves a private `preparing` record, performs AST discovery and
  candidate preflight **outside** the global mutex, and publishes the sealed
  catalogue only after rechecking expiry/source revision. Failed discovery
  releases the reservation.
- `Validate` has three phases: (1) lock briefly and reserve `validating`, copy
  the candidate and derive a context deadline from the transaction TTL; (2)
  release the global mutex, check the source and run the privileged oracle; (3)
  lock again to reject or approve after checking cancellation/expiry, candidate
  digest and source revision. Independent files can validate concurrently.
- A scope is held through `preparing`, `validating`, and `approved` until the
  relevant operation actually finishes and/or reaches `committed` or `rejected`.
  If cancellation or expiration occurs *during* a still-running validator,
  the manager requests cancellation but **does not release the scope early**.
  Client `Reject` during validation requests cancellation; final rejection
  happens after the validator returns. Other callers receive `ErrLocked`.
  Expired inactive records are reclaimed lazily.
- Errors are exported as Go sentinels (`ErrLocked`, `ErrState`, `ErrToken`,
  `ErrExpired`, `ErrStale`, `ErrValidatorUnavailable`). Clients can map them to
  structured error codes without parsing arbitrary text.
- Process-local audit events form a SHA-256 hash chain. Without durable,
  append-only trusted storage or independent anchoring, the chain is
  **not** immutable, tamper-proof, or a security attestation.

## Security limitations — do not merge as an executor

1. **No sandbox exists.** A goroutine is not isolation. Running `go test` on
   untrusted agent-written code in the host is out of scope and prohibited in
   this phase. Future isolated executors need independent adversarial tests.
2. The transaction manager now calls the Linux cooperative `atomicwriter`
   with a persistent sidecar `flock`, two revision/identity checks and a
   same-directory rename. It still has a TOCTOU window against *external*
   **non-cooperating** writers, and is neither a guaranteed filesystem CAS
   nor a multi-file commit. See `docs/atomicwriter-0.2.md`. A privileged
   committer still needs stricter workspace coordination and authorization.
3. The manager is in-memory only: restarting the process invalidates all
   capabilities and loses the audit history. This is safe against replay after
   restart, but not durable, nor a distributed transaction manager.
4. Tokens are bearer credentials: holders can exercise the privileges those
   tokens represent. Future network or multi-tenant deployment requires
   authenticated principals, TLS, authorization, quotas, and log redaction.
   Cryptographic random nonces plus server-side state are sufficient here;
   HMAC is useful if a later stateless token format is explicitly chosen.
5. Absolute normalized paths are not a filesystem sandbox or workspace access
   policy; symlinks, external file modifications, and identity/ownership must
   be handled by the privileged service before accepting arbitrary agent paths.
6. Tests using a synthetic in-package oracle prove state-machine invariants
   **under the assumed trusted validator**, not that real tests executed.
7. Cancellation is **cooperative** until the sandbox executor exists. A backend
   that never returns can retain its scope indefinitely; fail-closed is safer
   than reusing a file while untrusted work may still be active. The executor
   must enforce deadlines and kill whole process trees, independently tested.
8. New `preparing` reservations prevent duplicate/disputed discoveries but AST
   scanning has no context cancel API yet; constrain input size and processing
   time before exposing this service to hostile multi-tenant workloads.
9. Version hashes and an in-process scope map do not prevent external writes,
   TOCTOU races, symlink aliasing or hostile processes sharing a filesystem.

## Regression coverage

The in-package negative tests attempt forged candidate IDs, forged tokens,
reused commit tokens, unvalidated commits, canceled/failed validations,
source revision conflicts, scope lock clashes, expiry and concurrent replay.
New channel-coordinated tests cover independent-file parallel validation and
reconnaissance, duplicate validation rejection, conflicting-file lock retention,
client cancellation, non-cooperative validators, expiry, external file edits
and cleanup after completion. No flaky fixed `100ms` performance threshold is
used. `go test -race ./...` exercises manager locks and concurrent attempts.

## Next (Issue #2)

Implement a reviewed isolation backend and a privately wired validator that
verifies candidate-bound evidence (syntax/types/vet/build/tests/contracts),
then implement a durable, access-controlled commit mechanism. Until then,
`NewManager` intentionally cannot issue successful approval or commit tokens.
