#!/usr/bin/env bash
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
printf '1/3: EXPECTED failure in functional test, before patch\n'
if (cd "$tmp" && go test ./...); then
  printf 'ERROR: baseline unexpectedly passed\n' >&2
  exit 1
else
  printf 'Confirmed: unpatched behavior is wrong\n'
fi
printf '\n2/3: AST operation, in-memory validation, then write\n'
(cd "$root" && go run ./cmd/goai -file "$tmp/wallet.go" -patch "$tmp/fix.json" -write)
printf '\n3/3: Go functional test after patch\n'
(cd "$tmp" && go test ./...)
printf '\nDEMO PASSED\n'
