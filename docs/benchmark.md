# Fair comparison protocol

## Arms (same model, same task prompts, same time/token/tool budgets)

A. Plain Go agent with ordinary text patches + compiler diagnostics.
B. Plain Go agent with text patches + structured JSON diagnostics.
C. GoAI agent with strict structured patch operations and validation.

Use tasks representative of development work: localized bug fixes,
API changes, dependency upgrades, new tests, and refactoring. **The current
MVP only supports a small class of operator edits**, so running only those
tasks would unfairly favor C. Include tasks it cannot complete, and report
coverage as well as conditional success.

## Measure

- First-pass functional test pass rate and final task success rate.
- Rate of regressions on existing tests.
- Compilation/typecheck failure rate.
- Number of rejected operations / ambiguity rate.
- Number of model calls and iterations per success.
- Input/output tokens **including** diagnostics and tool responses.
- End-to-end latency and computational cost per correct solution.

Use paired tasks, independent seeds, and a sealed test suite. Collect
per-task outcomes and confidence intervals; don't make claims of improved
accuracy until the data supports them.

## Failure and safety boundaries

AST validity guarantees only syntactic shape, not type correctness. Typecheck
only guarantees certain language invariants, not business logic. Unit tests,
property tests, static checks and final user review remain necessary.
