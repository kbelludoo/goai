package sandboxcheck

import (
	"errors"
	"testing"

	"github.com/kbelludoo/goai/internal/isolationprobe"
)

func TestAssessRejectsHostAccessAndNamespaceReuse(t *testing.T) {
	host := HostNamespaces{Net: "net:[10]", Mount: "mnt:[20]", PID: "pid:[30]"}
	child := isolationprobe.Observation{NetNamespace: "net:[11]", MountNamespace: "mnt:[21]", PIDNamespace: "pid:[31]"}
	if err := assess(host, child); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		modify func(*isolationprobe.Observation)
	}{
		{"network leak", func(o *isolationprobe.Observation) { o.HostReachable = true }},
		{"filesystem leak", func(o *isolationprobe.Observation) { o.SentinelReadable = true }},
		{"shared net namespace", func(o *isolationprobe.Observation) { o.NetNamespace = host.Net }},
		{"shared mount namespace", func(o *isolationprobe.Observation) { o.MountNamespace = host.Mount }},
		{"shared PID namespace", func(o *isolationprobe.Observation) { o.PIDNamespace = host.PID }},
		{"missing namespace", func(o *isolationprobe.Observation) { o.NetNamespace = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := child
			tc.modify(&o)
			if err := assess(host, o); !errors.Is(err, ErrCompromised) {
				t.Fatalf("expected isolation failure, got %v", err)
			}
		})
	}
}
func TestAuditorRequiresTrustedProbe(t *testing.T) {
	if _, err := NewAuditor(""); err == nil {
		t.Fatal("empty trusted probe accepted")
	}
	a, err := NewAuditor("/some/trusted/probe")
	if err != nil {
		t.Fatal(err)
	}
	if a.Quarantined() {
		t.Fatal("new auditor should not be quarantined")
	}
	a.quarantine()
	if !a.Quarantined() {
		t.Fatal("failed to quarantine auditor")
	}
}
