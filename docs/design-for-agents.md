# Making Go friendlier to agents (without forking the language)

A design note, not a result. Claims about *what helps* are hypotheses with a
measurement plan in [benchmark.md](benchmark.md); claims about *what is
implemented* can be checked by running `go test ./...` and `scripts/demo.sh`.

## 0. "Friendly to AI" is five properties, not a vibe

A language is easy for an agent when its tooling gives, cheaply and reliably:

1. **Canonical text** — few valid spellings, so output is predictable.
2. **Stable identity** — one addressable name per declaration, shared by every
   tool, that survives reformatting and unrelated edits.
3. **Compact context** — a way to ask "what is here?" without reading everything.
4. **Closed edit space** — modifications expressible as a small set of checked
   operations, with preconditions, instead of free-text replacement.
5. **Resumable failure** — every rejection says whether retrying can help and
   exactly what to change.

Property 1 is a language-design product. Properties 2–5 are *interface*
products, and they cost nothing in language complexity. Most of the leverage is
therefore in tooling, not in syntax.

## 1. What Go already gets right

Go is already one of the most agent-friendly languages, mostly by accident of
its discipline:

- **gofmt is a canonical form.** There is one spelling of a program. An agent's
  output can be normalized before comparison, and diffs are meaningful. This is
  the single biggest advantage Go has over C++, Ruby, or TypeScript ecosystems.
- **Small grammar, no macros, no implicit conversions, no operator overloading.**
  Local reasoning works: a line's meaning rarely depends on distant magic.
- **Static types plus a very fast compiler.** Seconds-long feedback makes
  generate-check-repair loops affordable, which is exactly what an LLM needs.
- **Errors are values.** Verbose for humans, but they form a regular, greppable
  structure that models predict well.
- **`go list -json` is a genuinely good machine interface.** The module graph,
  files, imports, build constraints and test files are all there, structured.
- **`go test -json` and `go vet -json` exist.** Test outcomes and vet findings
  can be consumed without screen-scraping.
- **Generated-code convention** (`// Code generated ... DO NOT EDIT.`) is
  already widespread, which helps an agent avoid editing machine output.

So the honest answer to "how do we make Go friendlier to agents?" is: *keep the
language as it is and fix the interfaces*. Concretely, three gaps.

## 2. Gap 1 — canonical form exists, canonical identity does not

gofmt guarantees one spelling, but there is no single name for a declaration.
An agent composes some string from `go doc`, `gopls`, `go list` and the source:
`(*Wallet).Withdraw`, `wallet.Wallet.Withdraw`, `Withdraw (method on *Wallet)`,
`wallet.(*Wallet).Withdraw`. Those are all true and none is authoritative, so
every tool that must *act* on a symbol re-implements string matching against
source text — which is exactly the fragile part of the pre-0.2 version of this
repository (a bare method name plus a formatted left-hand side).

**Proposal:** a symbol identifier, printed by reconnaissance and accepted by
edits, with a normalization rule rather than a parser:

```
pkg.F                    package-level function
pkg.(*T).M               pointer-receiver method
pkg.(T).M                value-receiver method
pkg.T                    type
pkg.T.Field              struct field / interface method
```

Package-qualified, formatting-independent, and cheap: it can be derived from the
AST in one pass (`internal/engine/symbols.go`). The invariant that matters is
that the *same function* generates the identifier in `context` (read) and
`patch` (write); the moment those two paths disagree, an agent is guessing.

What this identifier still does not solve — and should be stated in any honest
README — is *identity across revisions*: a module-wide symbol table, generics
canonicalization, and build-constraint-aware views of the same package.

## 3. Gap 2 — diagnostics are prose, and refusals are dead ends

An agent's dominant failure mode is confident guessing. A tool's dominant
failure mode is a refusal that ends the conversation: `ambiguous selector`,
`expected ';'`, `exit status 2`. The interesting design question is not "how do
we produce fewer errors?" but "how do we make every error *carry its own fix*?"

Minimum viable structure per diagnostic:

| field | why |
| --- | --- |
| `code` | stable string; the machine branch, never parsed from prose |
| `file`, `line`, `column` | a range, so the caller can act without re-reading |
| `retryable` | separates "your input is wrong" from "the environment says no" |
| `hint` | one sentence describing the next attempt |
| `candidates` | located alternatives, each a ready-to-send retry payload |

That last row is the important one. In this repository an ambiguous patch
returns the matching sites *and*, per site, a `retry_target` object that is
itself a valid `target`. The loop becomes: send patch → get refusal → resend the
returned object, with no re-reading of the file and no string surgery. The same
principle applies to compiler diagnostics: `go/types` errors are wrapped with a
hint and marked retryable instead of being dumped as text.

There is a second, subtler point about refusals: **tools should also state what
they did not do.** A validator that stops at type-checking has not run tests, so
`next_actions` names `verify_with_tests` explicitly instead of letting an agent
infer correctness from `"ok": true`.

## 4. Gap 3 — context, not code, is the expensive resource

Agents do not need the file. They need enough of the file to decide what to
touch, plus a hash to prove which revision they saw. The 0.2 `context` mode
returns package name, imports, doc comments, one-line signatures, struct fields,
interface methods, and every assignment whose right side is a binary expression
— the exact set of editable sites for the supported operation — with line,
column and occurrence.

Design rules that turned out to matter:

- **One line per symbol.** Wrapped signatures and multi-line doc comments burn
  tokens; signatures are references to read, not code to paste.
- **Bound the prose.** Doc comments are truncated (`maxDocRunes`), and `-brief`
  drops them entirely.
- **Return the actionable set, not everything.** Listing only sites the patch
  language can address is what makes the output usable by a loop.
- **Include the hash.** `sha256` lets the next call pin
  `expected_file_sha256` and makes concurrent edits detectable instead of
  silently overwritten.
- **Never invent a second addressing scheme.** Sites carry the same symbol IDs
  the patch accepts.

## 5. Gap 4 — hidden context

Some of Go's agent-hostility is not interface, it is *invisible state* that a
local read cannot reveal. These are real costs, and mostly unfixable by a
protocol:

- structural interface satisfaction: `type I interface { M() }` is satisfied by a
  method elsewhere, with no `implements` clause to grep;
- embedding: method sets are composed implicitly, so "where is `Close` defined?"
  needs type information, not text search;
- build tags and file suffixes: the same directory is a different package under
  different constraints;
- generated code: it is valid Go, it is checked in, and it is the wrong place to
  edit;
- module graph and `replace` directives: the source you read is not always the
  source that compiles;
- cgo: two languages, one file.

Go's own answer to most of these is "use the type-checker", which is correct and
also means every agent-facing tool must be *package-aware* rather than
file-aware. This repository is honest that it is not yet: the type-check runs per
directory with a standard-library importer only.

## 6. What not to do

- **Do not let an LLM emit raw source through the edit channel.** The value here
  is the closed edit space plus preconditions plus atomic write; free-text diffs
  throw all three away.
- **Do not bake taste into the tool as a hard error.** The `reflect`/`unsafe`
  deny-list in this prototype is a demonstration policy, and it is the best
  example of the failure mode: it returns a refusal an agent cannot distinguish
  from a language rule. Policies belong in configuration, tagged as policy.
- **Do not hide errors to make results look successful.** A fluent summary of a
  failed edit is worse than an exit code.
- **Do not add prose to the contract.** No "explanation" fields an agent must
  parse; add a `code` and, if needed, a `hint`.
- **Do not claim the compiler proves correctness.** Type-checking, parsing and
  even `go vet` say nothing about behaviour; the demo exists to make that
  distinction visible.

## 7. Roadmap, in order of leverage

| Step | Change | Cost | Status |
| --- | --- | --- | --- |
| 1 | Versioned envelope, stable codes, `retryable`, `hint` | small | done (0.1 → 0.2) |
| 2 | Symbol IDs shared by context and patch | small | done |
| 3 | Reconnaissance mode with sites + hash + occurrences | small | done |
| 4 | Resumable ambiguity: `candidates[].retry_target` | small | done |
| 5 | Declarative policy instead of hard-coded deny-list | small | not done |
| 6 | Module-aware type-checking (`go list`/`gopls`) and per-package context | medium | not done |
| 7 | Candidate validated in a temp workspace, tests as a gate for `-write` | medium | not done |
| 8 | Operation set beyond one operator: rename local, add field, change signature, add test | large | not done |
| 9 | Multi-file transactions with a single precondition set | large | not done |

Steps 1–4 are the ones that generalize to *any* language with a formatter and a
type-checker; 5–9 are where Go's specific tooling makes the job easier than in
most ecosystems.

## 8. What upstream Go could plausibly adopt

Modest, non-breaking, and useful beyond agents:

- a documented, stable JSON schema for `go vet -json` and for compiler errors
  (`go build`'s `-json` output is still not a contract you can pin);
- a `go doc -json`-style structural symbol export with qualified identifiers,
  so the "canonical name" gap closes without a new language feature;
- making the generated-code marker queryable (`go list -json` exposing
  generated files) so tools can exclude machine output by default;
- keeping `gofmt`'s output *frozen* as an API: canonical form is the foundation
  everything else here rests on.

No language change is required for any of the above, and that is the point: Go
was designed for humans who read code in teams and expect uniformity. Those same
properties — canonical formatting, explicitness, fast checks — are what make a
program a good collaborator. The remaining work is to stop wrapping those
properties in human prose.
