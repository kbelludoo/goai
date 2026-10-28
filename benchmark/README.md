# GoAI Benchmark 0.1 — measurement contract (no benchmark claims)

**Status:** data contract + reader/validator only. This change does **not** run models, execute tests, curate 30 real tasks, or establish any advantage for GoAI.

## Experimental unit and provenance

Each UTF-8 JSONL line represents one complete **(task_id, modality, model ID + revision, replicate)** run. The harness, not the LLM, must write the log. Use a fixed/pinned model where possible and record model revision; temperature 0 does not guarantee determinism. The task manifest should be separate and include source repository, license, pinned vulnerable commit, patch/issue reference, category, public test invocation and hidden adjudication reference. Hidden test files, hashes of their content or execution details must **never** be included in the agent's prompt.

The four modalities are `m1_text`, `m2_text_diagnostics`, `m3_ast` and `m4_intent_catalog`. For M1/M2, `coverage.status=not_applicable`. For M3/M4, use `supported`, `unsupported` or `unknown` based on an independent representability check; record attempted unsupported actions and any fallback to text explicitly. The current GoAI v0.1 handles only one AST operation; the v0.2 catalogue branch proposes only `+` ↔ `-`. Consequently most general Go tasks are presently unsupported by M3/M4. Do **not** cherry-pick only tasks GoAI can represent and call it a general victory.

## Required run fields

- `schema_version`, `run_id`, `task_id`, `category`, `modality`, `replicate`: assign units and strata.
- `model` (`provider`, `id`, `revision`, `temperature`, optional `seed`): record which brain was held constant.
- `provenance`: SHA-256 of dataset, task manifest, actual prompt, actual tool policy, plus harness and vulnerable repository commits. These are reproducibility references, not trust attestations.
- `token_budget`, `wall_time_ms`: allocated model budget and actual elapsed wall time (including tools).
- `usage_source`: `provider`, `estimated`, or `unavailable`. `model_calls` hold per-call input/output, cached input (SUBSET of input), reasoning output (SUBSET of output), and latency. Provider usage should come directly from API usage metadata.
- `tool_events`: tool name, bytes returned, optional **estimated** tokens, whether output was sent to model, and latency. **Do not add tool tokens to provider totals**: tool responses sent to the model are counted again as input in the next model call.
- `edit_attempts`: numbered edit submissions, tool acceptance, latency, public test result, structured error code, and optional SHA-256 of the separately stored raw error log. An edit attempt is distinct from a model call.
- `coverage`: representability, candidate count, fallback occurrence and reason. Include unsupported attempts in the denominator for an intention-to-treat comparison.
- `outcome`: public and **held-out hidden** test results (`pass`, `fail`, `not_run`) and explicit end reason (`completed`, `unsupported`, `timeout`, `infra_error`, `budget_exhausted`). Results must come from a trusted offline judge; the agent's assertion must never populate hidden pass.

### Usage

```sh
go test ./internal/benchlog ./cmd/goai-bench
go run ./cmd/goai-bench -file /path/to/actual-runs.jsonl
```

The command rejects unknown fields, missing provenance, duplicate cells, invalid token subsets, and empty input. Output summarizes counts **without inventing win rates**. It excludes unavailable/estimated usage from provider-token totals and reports their counts separately. Do not calculate total token averages over rows with missing usage.

## Design safeguards before real benchmark

1. Source **30 real Go bug fixes** across three broad categories, with fixed snapshots and independent hidden tests. Verify actual licensing and benchmark suitability. Use the same tasks across all modalities; `n=30` is a pilot, not a definitive claim.
2. Keep agent prompts, model/API configuration, time and token budgets, test policy and orchestration constant; randomize trial order and use fresh isolated task workspaces.
3. Evaluate **primary end-to-end success over all assigned tasks**, including unsupported M4 tasks. Also report conditional success on representable tasks, but never use it alone. Pre-register whether M3/M4 may fall back to text; if allowed, report fallback rate and cost.
4. Paired binary hidden-test successes: McNemar or paired bootstrap confidence intervals. Paired token/time differences: distribution and bootstrap confidence intervals; Wilcoxon may be exploratory. Repeat trials/seeds if the budget allows, accounting for dependence. Multiple metrics require care to avoid cherry-picked claims.
5. Security: model-produced Go tests may execute arbitrary code. Do not use unisolated `go test` as a shortcut. A disposable workstation/VM with outbound networking disabled and resources capped is the benchmark prerequisite; worktrees and Docker alone are not a universal security guarantee. Do not merge or run the draft sandbox components assuming that their kernel isolation was already demonstrated.

## Dataset note

No 30-task manifest is included: inventing tasks or hidden-test outcomes would bias the experiment. Sample records are omitted to prevent synthetic examples from being mistaken for experimental data; tests construct fixtures in memory only.
