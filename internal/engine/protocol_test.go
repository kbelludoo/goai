package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

func parsePatchRaw(t *testing.T, raw string) Patch {
	t.Helper()
	p, err := ParsePatch([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected patch error: %v", err)
	}
	return p
}

func TestOutlineExposesSymbolsAndSites(t *testing.T) {
	code := `package calc

// Wallet holds a balance.
type Wallet struct {
	Balance int
}

// Withdraw removes amount from the balance.
func (w *Wallet) Withdraw(amount int) error {
	w.Balance = w.Balance + amount
	return nil
}

// Total sums two values.
func Total(a, b int) int { return a + b }
`
	path, src := prepare(t, code)
	out := Outline(path, src, OutlineOptions{})
	if !out.OK {
		t.Fatalf("unexpected diagnostics: %+v", out.Diagnostics)
	}
	if out.Package != "calc" || out.Protocol != Protocol {
		t.Fatalf("unexpected envelope: %+v", out)
	}
	byID := map[string]Symbol{}
	for _, s := range out.Symbols {
		byID[s.ID] = s
	}
	for _, want := range []string{"calc.Wallet", "calc.Wallet.Balance", "calc.(*Wallet).Withdraw", "calc.Total"} {
		if _, ok := byID[want]; !ok {
			t.Fatalf("missing symbol %q in %+v", want, out.Symbols)
		}
	}
	if byID["calc.(*Wallet).Withdraw"].Kind != "method" {
		t.Fatalf("expected method kind: %+v", byID["calc.(*Wallet).Withdraw"])
	}
	if got := byID["calc.Total"].Signature; got != "func Total(a, b int) int" {
		t.Fatalf("unexpected signature %q", got)
	}
	if got := byID["calc.Wallet.Balance"].Signature; got != "int" {
		t.Fatalf("unexpected field signature %q", got)
	}
	if len(out.Targets) != 1 {
		t.Fatalf("expected exactly one editable site, got %+v", out.Targets)
	}
	site := out.Targets[0]
	if site.Symbol != "calc.(*Wallet).Withdraw" || site.AssignmentLHS != "w.Balance" || site.Operator != "+" {
		t.Fatalf("unexpected site: %+v", site)
	}
	if site.RetryTarget.Occurrence == nil || *site.RetryTarget.Occurrence != 1 {
		t.Fatalf("retry target must carry the occurrence: %+v", site.RetryTarget)
	}
}

func TestOutlineBriefAndTypecheck(t *testing.T) {
	path, src := prepare(t, "package calc\n// Doc is a value.\nvar Doc = 1\nfunc Use() int { return Doc }\n")
	brief := Outline(path, src, OutlineOptions{Brief: true})
	for _, s := range brief.Symbols {
		if s.Doc != "" || s.Signature != "" {
			t.Fatalf("brief mode must omit prose: %+v", s)
		}
	}

	broken := []byte("package calc\nfunc F(a, b string) string { x := a - b; return x }\n")
	checked := Outline(path, broken, OutlineOptions{Typecheck: true})
	if checked.OK {
		t.Fatal("typecheck option must surface the type error")
	}
	if checked.Diagnostics[0].Code != "GOAI-TYPE-001" {
		t.Fatalf("expected GOAI-TYPE-001: %+v", checked.Diagnostics)
	}
}

func TestCheckReportsWithoutEditing(t *testing.T) {
	path, src := prepare(t, "package calc\nfunc F(a, b int) int { return a + b }\n")
	if out := Check(path, src); !out.OK || out.Action != "check" || len(out.NextActions) == 0 {
		t.Fatalf("expected a clean check: %+v", out)
	}
	broken := []byte("package calc\nfunc F(a, b string) string { return a - b }\n")
	out := Check(path, broken)
	if out.OK || out.Diagnostics[0].Code != "GOAI-TYPE-001" {
		t.Fatalf("expected a type error: %+v", out)
	}
	if out.Diagnostics[0].Line == 0 || out.Diagnostics[0].Hint == "" || !out.Diagnostics[0].Retryable {
		t.Fatalf("diagnostic must be actionable: %+v", out.Diagnostics[0])
	}
}

func TestAmbiguityReturnsCandidatesAndRetryAction(t *testing.T) {
	path, src := prepare(t, "package calc\nfunc Calculate(a, b int) int { x := a + b; x = a + b; return x }\n")
	r := Apply(path, src, patch(t, "x", "+", "-"))
	if r.OK {
		t.Fatal("expected refusal")
	}
	d := r.Diagnostics[0]
	if d.Code != "GOAI-AMBIGUOUS-001" || !d.Retryable || d.Hint == "" {
		t.Fatalf("unexpected diagnostic: %+v", d)
	}
	if len(d.Candidates) != 2 {
		t.Fatalf("expected two candidates: %+v", d.Candidates)
	}
	if d.Candidates[1].Occurrence != 2 || d.Candidates[1].Line == 0 {
		t.Fatalf("candidates must be ordered and located: %+v", d.Candidates[1])
	}
	if len(r.NextActions) != 1 || r.NextActions[0].Kind != "retry_with_occurrence" {
		t.Fatalf("refusal must say how to retry: %+v", r.NextActions)
	}
}

func TestOccurrenceSelectsOneSite(t *testing.T) {
	path, src := prepare(t, "package calc\nfunc Calculate(a, b int) int { x := a + b; x = a + b; return x }\n")
	occurrence := 2
	p := patch(t, "x", "+", "-")
	p.Target.Occurrence = &occurrence
	r := Apply(path, src, p)
	if !r.OK {
		t.Fatalf("unexpected refusal: %+v", r.Diagnostics)
	}
	if !strings.Contains(r.UpdatedSource, "x = a - b") || strings.Contains(r.UpdatedSource, "x := a - b") {
		t.Fatalf("wrong occurrence edited:\n%s", r.UpdatedSource)
	}
	if len(r.NextActions) != 2 {
		t.Fatalf("expected apply_write and verify_with_tests: %+v", r.NextActions)
	}
}

func TestOccurrenceOutOfRangeIsRetryable(t *testing.T) {
	path, src := prepare(t, "package calc\nfunc Calculate(a, b int) int { x := a + b; return x }\n")
	occurrence := 7
	p := patch(t, "x", "+", "-")
	p.Target.Occurrence = &occurrence
	r := Apply(path, src, p)
	if r.OK || r.Diagnostics[0].Code != "GOAI-TARGET-002" || !r.Diagnostics[0].Retryable {
		t.Fatalf("expected out-of-range refusal: %+v", r)
	}
	if len(r.Diagnostics[0].Candidates) != 1 {
		t.Fatalf("expected candidates: %+v", r.Diagnostics[0])
	}
}

func TestSymbolAndReceiverSelectors(t *testing.T) {
	code := `package calc

type A struct{ n int }

type B struct{ n int }

func (r *A) Add(v int) int {
	r.n = r.n + v
	return r.n
}

func (r *B) Add(v int) int {
	r.n = r.n + v
	return r.n
}
`
	path, src := prepare(t, code)
	ambiguous := parsePatchRaw(t, `{"action":"replace_binary_operator","target":{"function":"Add","assignment_lhs":"r.n"},"expected_operator":"+","new_operator":"-"}`)
	r := Apply(path, src, ambiguous)
	if r.OK || len(r.Diagnostics[0].Candidates) != 2 {
		t.Fatalf("expected receiver ambiguity: %+v", r)
	}
	if r.Diagnostics[0].Candidates[0].Symbol != "calc.(*A).Add" || r.Diagnostics[0].Candidates[1].Symbol != "calc.(*B).Add" {
		t.Fatalf("unexpected candidate symbols: %+v", r.Diagnostics[0].Candidates)
	}

	bySymbol := parsePatchRaw(t, `{"action":"replace_binary_operator","target":{"symbol":"calc.(*B).Add","assignment_lhs":"r.n"},"expected_operator":"+","new_operator":"-"}`)
	out := Apply(path, src, bySymbol)
	if !out.OK {
		t.Fatalf("symbol selector failed: %+v", out.Diagnostics)
	}
	if !strings.Contains(out.UpdatedSource, "func (r *B) Add(v int) int {\n\tr.n = r.n - v") {
		t.Fatalf("wrong method edited:\n%s", out.UpdatedSource)
	}

	byReceiver := parsePatchRaw(t, `{"action":"replace_binary_operator","target":{"function":"Add","receiver":"*A","assignment_lhs":"r.n"},"expected_operator":"+","new_operator":"-"}`)
	out = Apply(path, src, byReceiver)
	if !out.OK {
		t.Fatalf("receiver selector failed: %+v", out.Diagnostics)
	}
	if !strings.Contains(out.UpdatedSource, "func (r *A) Add(v int) int {\n\tr.n = r.n - v") {
		t.Fatalf("wrong method edited:\n%s", out.UpdatedSource)
	}
}

func TestCandidateRetryTargetRoundTripsThroughJSON(t *testing.T) {
	path, src := prepare(t, "package calc\nfunc Calculate(a, b int) int { x := a + b; x = a + b; return x }\n")
	first := Apply(path, src, patch(t, "x", "+", "-"))
	if first.OK || len(first.Diagnostics[0].Candidates) != 2 {
		t.Fatalf("expected ambiguity: %+v", first)
	}
	retry := map[string]any{
		"action":            "replace_binary_operator",
		"target":            first.Diagnostics[0].Candidates[1].RetryTarget,
		"expected_operator": "+",
		"new_operator":      "-",
	}
	raw, err := json.Marshal(retry)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParsePatch(raw)
	if err != nil {
		t.Fatalf("retry target rejected by ParsePatch: %v (%s)", err, raw)
	}
	second := Apply(path, src, p)
	if !second.OK {
		t.Fatalf("retry failed: %+v", second.Diagnostics)
	}
	if strings.Count(second.UpdatedSource, "a - b") != 1 {
		t.Fatalf("retry edited the wrong site:\n%s", second.UpdatedSource)
	}
}

func TestTargetHintPointsAtContext(t *testing.T) {
	path, src := prepare(t, "package calc\nfunc Calculate(a, b int) int { return a + b }\n")
	r := Apply(path, src, patch(t, "x", "+", "-"))
	if r.OK || r.Diagnostics[0].Code != "GOAI-TARGET-001" {
		t.Fatalf("expected unknown target: %+v", r)
	}
	if !strings.Contains(r.Diagnostics[0].Hint, "goai context") || !r.Diagnostics[0].Retryable {
		t.Fatalf("hint must point at the reconnaissance mode: %+v", r.Diagnostics[0])
	}
	if len(r.NextActions) != 1 || r.NextActions[0].Kind != "reconnoiter" {
		t.Fatalf("unexpected next actions: %+v", r.NextActions)
	}
}

func TestRejectConflictingSelectors(t *testing.T) {
	for _, raw := range []string{
		`{"action":"replace_binary_operator","target":{"function":"F","symbol":"calc.F","assignment_lhs":"x"},"expected_operator":"+","new_operator":"-"}`,
		`{"action":"replace_binary_operator","target":{"function":"F","assignment_lhs":"x","occurrence":0},"expected_operator":"+","new_operator":"-"}`,
		`{"action":"replace_binary_operator","target":{"assignment_lhs":"x"},"expected_operator":"+","new_operator":"-"}`,
		`{"action":"replace_binary_operator","target":{"function":"F"},"expected_operator":"+","new_operator":"-"}`,
	} {
		if _, err := ParsePatch([]byte(raw)); err == nil {
			t.Fatalf("expected invalid patch: %s", raw)
		}
	}
}

func TestWithoutKindKeepsOrder(t *testing.T) {
	actions := []NextAction{{Kind: "a"}, {Kind: "apply_write"}, {Kind: "b"}}
	out := WithoutKind(actions, "apply_write")
	if len(out) != 2 || out[0].Kind != "a" || out[1].Kind != "b" {
		t.Fatalf("unexpected actions: %+v", out)
	}
	if len(actions) != 3 {
		t.Fatal("WithoutKind must not mutate the input")
	}
}
