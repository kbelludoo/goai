# GoAI Benchmark 0.1 — constant-agent driver (increment)

**Status: orchestration library with fully scripted unit tests. No real model API, task dataset, hidden-test judge, code-execution backend or real benchmark results.** This is deliberately separate from the draft sandbox PR chain.

`internal/benchdriver.Run` is a bounded, standard-library-only Go tool loop. The same `Model.Next()` and immutable `SystemPrompt` are used for all four modalities, while `ToolSpec` advertises a restricted set of actions. Models receive an issue description, public context, public tool replies and no private hidden-test inputs. A production harness must still ensure that the external model/provider never receives hidden artifacts through any other channel.

| Mode | Tools besides common `read_file`, `run_tests` | Control variable |
|---|---|---|
| M1 text | `apply_text_patch` | Raw public test feedback |
| M2 structured | `apply_text_patch` | Structured public diagnostics **must be produced by the future executor**, not by this loop |
| M3 AST | `apply_ast_mutation`, optional explicit `fallback_to_text_patch` | Agent writes one versioned AST operation |
| M4 intent/catalog | `request_catalog`, `choose_candidate`, optional fallback | Catalogue request before any choice; trusted backend owns IDs/patches |

A private `ToolExecutor` is responsible for implementing *all* actual tools and public tests in a sandboxed task copy. The driver blocks unadvertised tools and malformed JSON before delegation. This is an API boundary, not authorization of actual patches: the executor must check tool arguments, path scope, revision, catalogue integrity and what tests really ran. The public-test status is read only from `ToolResult` emitted by this trusted backend; model prose cannot change it. The agent never receives an interface to execute or read held-out hidden tests. An independent offline judge must populate `Outcome.HiddenTests` **after** the agent run, in a separate trusted process.

The driver returns a `benchlog.Run` compatible with PR #11: unique model calls, provider-reported token counts when present, tool events, edit attempts, representability, explicit fallback, and hashes of the initial model-visible message array and advertised tool policy. Tool-return token estimates do not get added to provider token usage a second time. If model usage is unavailable, totals are **missing**, not zero. Run provenance `DatasetSHA256`, `TaskSHA256`, commits, category, and model revision must be supplied by the experiment controller from pinned input artifacts. Budget enforcement is only reliable when the provider exposes complete usage; always also bound turns, output bytes and elapsed time.

## Local verification (does not execute generated code)

```sh
go test ./internal/benchdriver ./internal/benchlog
go test -race ./internal/benchdriver ./internal/benchlog
go vet ./...
```

Scripted tests exercise all four tool policies, premature M4 choices, missing usage, explicit fallback, denied hidden-tool calls, missing provider response, and deterministic provenance digests. All generated model responses and tool statuses in these tests are synthetic. **Never publish their totals as benchmark measurements.**

## Work remaining before even one real E2E trial

1. Pin and independently reproduce **one real Go bug fix** with its issue, pre-fix commit, public tests and privately held regression tests. Vet repository/task licenses.
2. Implement one model provider adapter with actual response-usage metadata and a fixed model revision/configuration. Merely setting temperature to 0 is not a reproducibility guarantee.
3. Implement real versioned workspaces and **reviewed isolated test execution**, plus M1 text patches, M2 structured diagnostic conversion, M3 engine AST edit and M4 catalogue/choice adapters. Until then `ToolExecutor` must not invoke untrusted code.
4. Enforce uniform time/attempt/tool budgets and randomized paired execution order. Include unsupported tasks in M3/M4 denominators; pre-register fallback policy and record both coverage and cost.
5. Run hidden tests exclusively offline, outside model-visible context; attribute trusted results to each stored run. Only then aggregate model efficacy and token costs.

## Note on the separate cgroup launcher fixes

The third-party launcher cherry-pick sequence discussed in the project is **not integrated into this benchmark PR**. The security PRs remain draft; no sandbox guarantee can be inferred from this driver.
