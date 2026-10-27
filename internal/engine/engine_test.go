package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func prepare(t *testing.T, code string) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "calc.go")
	if err := os.WriteFile(path, []byte(code), 0644); err != nil {
		t.Fatal(err)
	}
	return path, []byte(code)
}

func patch(t *testing.T, lhs, from, to string) Patch {
	t.Helper()
	raw := `{"action":"replace_binary_operator","target":{"function":"Calculate","assignment_lhs":"` + lhs + `"},"expected_operator":"` + from + `","new_operator":"` + to + `"}`
	p, err := ParsePatch([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValidChangeInMemory(t *testing.T) {
	path, src := prepare(t, "package calc\nfunc Calculate(a,b int) int { x := a+b; return x }\n")
	p := patch(t, "x", "+", "-")
	r := Apply(path, src, p)
	if !r.OK {
		t.Fatalf("unexpected failure: %+v", r.Diagnostics)
	}
	if !strings.Contains(r.UpdatedSource, "x := a - b") {
		t.Fatal(r.UpdatedSource)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != string(src) {
		t.Fatal("Apply must not modify original")
	}
	if err := WriteAtomic(path, src, r.UpdatedSource); err != nil {
		t.Fatal(err)
	}
	onDisk, _ = os.ReadFile(path)
	if !strings.Contains(string(onDisk), "x := a - b") {
		t.Fatal("atomic write failed")
	}
}

func TestRejectAmbiguity(t *testing.T) {
	path, src := prepare(t, "package calc\nfunc Calculate(a,b int) int { x := a+b; x = a+b; return x }\n")
	r := Apply(path, src, patch(t, "x", "+", "-"))
	if r.OK || r.Diagnostics[0].Code != "GOAI-AMBIGUOUS-001" {
		t.Fatalf("expected ambiguity: %+v", r)
	}
}

func TestRejectTypeError(t *testing.T) {
	path, src := prepare(t, "package calc\nfunc Calculate(a,b string) string { x := a+b; return x }\n")
	r := Apply(path, src, patch(t, "x", "+", "-"))
	if r.OK || r.Diagnostics[0].Code != "GOAI-TYPE-001" {
		t.Fatalf("expected type error: %+v", r)
	}
}

func TestRejectStalePatch(t *testing.T) {
	path, src := prepare(t, "package calc\nfunc Calculate(a,b int) int { x := a-b; return x }\n")
	r := Apply(path, src, patch(t, "x", "+", "-"))
	if r.OK || r.Diagnostics[0].Code != "GOAI-CONFLICT-002" {
		t.Fatalf("expected stale precondition: %+v", r)
	}
}

func TestRejectWrongHash(t *testing.T) {
	path, src := prepare(t, "package calc\nfunc Calculate(a,b int) int { x := a+b; return x }\n")
	p := patch(t, "x", "+", "-")
	p.ExpectedFileSHA256 = strings.Repeat("0", 64)
	r := Apply(path, src, p)
	if r.OK || r.Diagnostics[0].Code != "GOAI-CONFLICT-001" {
		t.Fatalf("expected hash conflict: %+v", r)
	}
}

func TestRejectExtraJSONAndUnknownFields(t *testing.T) {
	for _, raw := range []string{
		`{"action":"replace_binary_operator"} {"another":true}`,
		`{"action":"replace_binary_operator","invented":true}`,
		`{"action":"bad"}`,
	} {
		if _, err := ParsePatch([]byte(raw)); err == nil {
			t.Fatalf("expected invalid patch: %s", raw)
		}
	}
}

func TestRejectUnsafe(t *testing.T) {
	path, src := prepare(t, "package calc\nimport \"unsafe\"\nfunc Calculate(a,b int) int { _ = unsafe.Sizeof(a); x := a+b; return x }\n")
	r := Apply(path, src, patch(t, "x", "+", "-"))
	if r.OK || r.Diagnostics[0].Code != "GOAI-POLICY-001" {
		t.Fatalf("expected policy rejection: %+v", r)
	}
}

func TestRejectWriteConflict(t *testing.T) {
	path, src := prepare(t, "package calc\nfunc Calculate(a,b int) int { x := a+b; return x }\n")
	r := Apply(path, src, patch(t, "x", "+", "-"))
	if !r.OK {
		t.Fatal(r.Diagnostics)
	}
	if err := os.WriteFile(path, []byte("changed"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(path, src, r.UpdatedSource); err == nil {
		t.Fatal("expected conflict")
	}
}
