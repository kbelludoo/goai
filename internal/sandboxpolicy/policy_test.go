package sandboxpolicy

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

func TestParseLimits(t *testing.T) {
	cases := []struct {
		profile string
		want    Limits
		wantErr string
	}{
		{"default", DefaultLimits(), ""},
		{"512MiB/50%/100", Limits{MemoryMaxBytes: 512 << 20, CPUQuotaUS: 50000, CPUPeriodUS: 100000, PIDsMax: 100}, ""},
		{"2GiB/200%/64", Limits{MemoryMaxBytes: 2 << 30, CPUQuotaUS: 200000, CPUPeriodUS: 100000, PIDsMax: 64}, ""},
		{"1GB/1000%/1", Limits{MemoryMaxBytes: 1_000_000_000, CPUQuotaUS: 1_000_000, CPUPeriodUS: 100000, PIDsMax: 1}, ""},
		{"", Limits{}, "GOAI-POLICY-002"},
		{"512/50%/100", Limits{}, "GOAI-POLICY-005"},
		{"512MiB/0%/100", Limits{}, "GOAI-POLICY-006"},
		{"512MiB/50", Limits{}, "GOAI-POLICY-006"},
		{"512MiB/50%/0", Limits{}, "GOAI-POLICY-004"},
		{"512MiB/50%", Limits{}, "GOAI-POLICY-003"},
		{"9999999999GiB/50%/10", Limits{}, "GOAI-POLICY-005"},
	}
	for _, tc := range cases {
		got, err := ParseLimits(tc.profile)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%q: wanted %s, got %v", tc.profile, tc.wantErr, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tc.profile, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q: got %+v, want %+v", tc.profile, got, tc.want)
		}
	}
}

func TestEmptyLimitsAreNotUnlimited(t *testing.T) {
	// The zero value must never be interpreted as "no limits".
	if _, err := ParseLimits(""); err == nil {
		t.Fatal("empty profile accepted")
	}
	if _, err := ParseLimits("max/max/max"); err == nil {
		t.Fatal("unlimited profile accepted")
	}
}

func TestDenyRequiresNoFailureAndNoUnknown(t *testing.T) {
	ok := Decision{Checks: []Check{{Name: "a", Status: StatusOK}, {Name: "b", Status: StatusWarn}}}
	ok.deny()
	if !ok.Allowed {
		t.Fatal("warnings must not deny")
	}
	unknown := Decision{Checks: []Check{{Name: "a", Status: StatusOK}, {Name: "b", Status: StatusUnknown}}}
	unknown.deny()
	if unknown.Allowed {
		t.Fatal("an unproven check must deny")
	}
	failed := Decision{Checks: []Check{{Name: "a", Status: StatusFail, Code: "GOAI-X-001"}}}
	failed.deny()
	if failed.Allowed || len(failed.Reasons) != 1 || failed.Reasons[0] != "GOAI-X-001" {
		t.Fatalf("unexpected decision: %+v", failed)
	}
}

func TestEvaluateDeniesWithoutRoot(t *testing.T) {
	d := Evaluate("", DefaultLimits())
	if d.Allowed {
		t.Fatal("evaluated as allowed without a delegation root")
	}
	if d.Protocol != Protocol || d.Mode != "sandbox" {
		t.Fatalf("unexpected envelope: %+v", d)
	}
	if !strings.Contains(strings.Join(d.Reasons, " "), "GOAI-CGROUP-004") {
		t.Fatalf("missing configuration reason: %+v", d.Reasons)
	}
	if err := d.Err(); err == nil {
		t.Fatal("Err must report denial")
	}
}

func TestEvaluateDeniesUnusableLimits(t *testing.T) {
	for _, limits := range []Limits{
		{},
		{MemoryMaxBytes: 1 << 20, CPUQuotaUS: 50000, CPUPeriodUS: 100000, PIDsMax: 10}, // under cgroupv2 minimum
		{MemoryMaxBytes: 512 << 20, CPUQuotaUS: 0, CPUPeriodUS: 100000, PIDsMax: 10},
	} {
		d := Evaluate("/sys/fs/cgroup", limits)
		if d.Allowed {
			t.Fatalf("accepted unusable limits %+v", limits)
		}
	}
}

func TestEvaluateDeniesUntrustedRoot(t *testing.T) {
	for _, root := range []string{"/tmp", "/etc", "relative/path", "/sys/fs/cgroup"} {
		d := Evaluate(root, DefaultLimits())
		if d.Allowed {
			t.Fatalf("accepted untrusted delegation root %q: %+v", root, d.Checks)
		}
		if !strings.Contains(strings.Join(d.Reasons, " "), "GOAI-CGROUP-004") {
			t.Fatalf("expected delegation root reason for %q: %+v", root, d.Reasons)
		}
	}
}

func TestProbeRequiresTrustedAbsoluteBinary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-specific probe")
	}
	for _, binary := range []string{"", "true", "./true"} {
		if _, err := ProbeAtomicPlacement("/sys/fs/cgroup", DefaultLimits(), binary); err == nil {
			t.Fatalf("accepted untrusted probe binary %q", binary)
		}
	}
}

func TestProbeRefusesWhenOtherChecksFail(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-specific probe")
	}
	if _, err := ProbeAtomicPlacement("", DefaultLimits(), "/bin/true"); err == nil {
		t.Fatal("probe ran without a delegation root")
	}
}

func TestNonLinuxDeniesEverywhere(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("linux has a real evaluator")
	}
	d := Evaluate("/whatever", DefaultLimits())
	if d.Allowed || !errors.Is(d.Err(), d.Err()) {
		t.Fatalf("non-linux must deny: %+v", d)
	}
}
