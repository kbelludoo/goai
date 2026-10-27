package main

import (
	"errors"
	"flag"
	"testing"
)

func TestParseArgsModeBeforeFlags(t *testing.T) {
	opts, err := parseArgs([]string{"context", "-file", "wallet.go", "-brief", "-typecheck"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.mode != "context" || opts.file != "wallet.go" || !opts.brief || !opts.typecheck {
		t.Fatalf("flags after the mode were not parsed: %+v", opts)
	}
}

func TestParseArgsLegacyInvocation(t *testing.T) {
	opts, err := parseArgs([]string{"-file", "wallet.go", "-patch", "fix.json", "-write"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.mode != "patch" || opts.file != "wallet.go" || opts.patch != "fix.json" || !opts.write {
		t.Fatalf("legacy invocation changed: %+v", opts)
	}
}

func TestParseArgsDiagnosticCodes(t *testing.T) {
	cases := []struct {
		args []string
		code string
	}{
		{nil, "GOAI-USAGE-001"},
		{[]string{"context"}, "GOAI-USAGE-001"},
		{[]string{"eval", "-file", "x.go"}, "GOAI-USAGE-003"},
		{[]string{"context", "-file", "x.go", "extra"}, "GOAI-USAGE-002"},
		{[]string{"check", "-file"}, "GOAI-USAGE-004"},
	}
	for _, tc := range cases {
		_, err := parseArgs(tc.args)
		var usage *usageErr
		if !errors.As(err, &usage) {
			t.Fatalf("args %v: expected usage error, got %v", tc.args, err)
		}
		if usage.code != tc.code {
			t.Fatalf("args %v: expected %s, got %s", tc.args, tc.code, usage.code)
		}
	}
}

func TestParseArgsHelp(t *testing.T) {
	if _, err := parseArgs([]string{"-h"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("expected help to be reported as ErrHelp, got %v", err)
	}
}
