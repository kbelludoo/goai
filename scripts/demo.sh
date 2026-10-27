#!/usr/bin/env bash
# End-to-end demonstration of the agent-facing contract:
#   1. reconnaissance (compact context, stable symbol IDs)
#   2. a refusal that is resumable (ambiguity returns candidates)
#   3. a validated edit, written atomically
#   4. a functional test that the type-checker cannot replace
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cp "$root"/testdata/wallet/*.go "$tmp/"
cp "$root"/testdata/wallet/fix.json "$tmp/"
cat > "$tmp/go.mod" <<'MOD'
module example.com/goai-demo-wallet

go 1.23
MOD

printf '1/4: EXPECTED failure in functional test, before patch\n'
if (cd "$tmp" && go test ./...); then
  printf 'ERROR: baseline unexpectedly passed\n' >&2
  exit 1
fi
printf 'Confirmed: unpatched behavior is wrong\n'

printf '\n2/4: context - identifiers and editable sites, without the file body\n'
(cd "$root" && go run ./cmd/goai context -file "$tmp/wallet.go" -brief) > "$tmp/context.json"
grep -qF '"wallet.(*Wallet).Withdraw"' "$tmp/context.json"
grep -qF '"w.Balance"' "$tmp/context.json"
grep -E '"(id|symbol|assignment_lhs|operator)"' "$tmp/context.json" > "$tmp/summary.txt" || true
head -12 "$tmp/summary.txt"
printf 'Confirmed: the patch target below comes from this output\n'

printf '\n3/4: ambiguous edit is refused with machine-readable candidates\n'
mkdir -p "$tmp/amb"
cat > "$tmp/amb/amb.go" <<'GO'
package amb

func Total(a, b int) int {
	x := a + b
	x = a + b
	return x
}
GO
cat > "$tmp/amb/amb.json" <<'JSON'
{
  "action": "replace_binary_operator",
  "target": { "function": "Total", "assignment_lhs": "x" },
  "expected_operator": "+",
  "new_operator": "-"
}
JSON
if (cd "$root" && go run ./cmd/goai -file "$tmp/amb/amb.go" -patch "$tmp/amb/amb.json") > "$tmp/amb.out"; then
  printf 'ERROR: ambiguous patch was accepted\n' >&2
  exit 1
fi
grep -qF 'GOAI-AMBIGUOUS-001' "$tmp/amb.out"
grep -qF '"retry_target"' "$tmp/amb.out"
grep -qF '"occurrence": 2' "$tmp/amb.out"
printf 'Confirmed: refusal lists candidates plus the exact retry patch\n'

printf '\n4/4: AST operation, in-memory validation, then atomic write\n'
(cd "$root" && go run ./cmd/goai -file "$tmp/wallet.go" -patch "$tmp/fix.json" -write)
printf '\nGo functional test after patch\n'
(cd "$tmp" && go test ./...)
printf '\nDEMO PASSED\n'
