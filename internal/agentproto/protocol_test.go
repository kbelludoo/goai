package agentproto

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kbelludoo/goai/internal/engine"
)

func fixture(t *testing.T) (Transaction, *CandidateCatalog, Candidate) {
	t.Helper()
	rev := strings.Repeat("a", 64)
	selector := SemanticSelector{File: "wallet.go", Declaration: "Withdraw", FileSHA256: rev, MatchPolicy: "exactly_one"}
	tx, err := NewTransaction("tx-wallet", selector, Intent{Kind: FixArithmeticLogic})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := NewCandidateCatalog(tx.ID, rev)
	if err != nil {
		t.Fatal(err)
	}
	patch := engine.Patch{Action: "replace_binary_operator", ExpectedOperator: "+", NewOperator: "-", ExpectedFileSHA256: rev}
	patch.Target.Function = "Withdraw"
	patch.Target.AssignmentLHS = "w.Balance"
	candidate, err := catalog.Register(patch, strings.Repeat("b", 64), "Change + to -")
	if err != nil {
		t.Fatal(err)
	}
	if err := catalog.Seal(); err != nil {
		t.Fatal(err)
	}
	return tx, catalog, candidate
}
func reportFor(tx Transaction) ValidationReport {
	out := ValidationReport{TransactionID: tx.ID, RevisionSHA256: tx.Target.FileSHA256, CandidateID: tx.CandidateID,
		CandidateDigest: tx.CandidateDigest, CandidateOutputSHA256: tx.CandidateOutputSHA256, PolicySHA256: strings.Repeat("e", 64)}
	for _, name := range []GateName{ParseGate, TypesGate, VetGate, BuildGate, TestsGate} {
		out.Gates = append(out.Gates, GateResult{Name: name, Status: Pass})
	}
	return out
}
func TestTransactionLifecycle(t *testing.T) {
	tx, catalog, c := fixture(t)
	if err := tx.Transition(Committed); err == nil {
		t.Fatal("cannot commit without validation")
	}
	if err := tx.SelectCandidate(catalog, c.ID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Transition(Validated); err == nil {
		t.Fatal("validation must use bound evidence")
	}
	if err := tx.MarkValidated(reportFor(tx)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Transition(Committed); err != nil {
		t.Fatal(err)
	}
	if err := tx.Transition(Proposed); err == nil {
		t.Fatal("commit must be terminal")
	}
}
func TestRejectedTerminal(t *testing.T) {
	tx, _, _ := fixture(t)
	if err := tx.Transition(Rejected); err != nil {
		t.Fatal(err)
	}
	if err := tx.Transition(Pending); err == nil {
		t.Fatal("rejected must be terminal")
	}
}
func TestForgedCandidateRejected(t *testing.T) {
	tx, catalog, c := fixture(t)
	if err := tx.SelectCandidate(catalog, "mut_01010101010101010101"); err == nil {
		t.Fatal("accepted never-issued candidate")
	}
	if tx.State != Pending || tx.CandidateID != "" {
		t.Fatal("failed choice modified transaction")
	}
	if err := tx.SelectCandidate(catalog, c.ID); err != nil {
		t.Fatal(err)
	}
	tx2, _, _ := fixture(t)
	tx2.Target.FileSHA256 = strings.Repeat("0", 64)
	if err := tx2.SelectCandidate(catalog, c.ID); err == nil {
		t.Fatal("stale revision accepted")
	}
}
func TestCandidateCatalogueImmutableAndLazy(t *testing.T) {
	tx, catalog, c := fixture(t)
	menu := catalog.Response()
	b, err := json.Marshal(menu)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "ast_patch") || strings.Contains(string(b), "expected_operator") {
		t.Fatal("catalogue leaked executable patch")
	}
	menu.Candidates[0].ID = "forged"
	menu.Candidates[0].Digest = strings.Repeat("f", 64)
	actual, patch, err := catalog.Resolve(c.ID, tx.ID, tx.Target.FileSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if actual.Digest != c.Digest || patch.NewOperator != "-" {
		t.Fatal("wire response changed registry")
	}
	if _, _, err := catalog.Resolve("forged", tx.ID, tx.Target.FileSHA256); err == nil {
		t.Fatal("unknown patch resolved")
	}
}
func TestEvidenceCannotReplayAcrossCandidates(t *testing.T) {
	a, catalogA, cA := fixture(t)
	if err := a.SelectCandidate(catalogA, cA.ID); err != nil {
		t.Fatal(err)
	}
	r := reportFor(a)
	b, catalogB, _ := fixture(t)
	patch := engine.Patch{Action: "replace_binary_operator", ExpectedOperator: "-", NewOperator: "+", ExpectedFileSHA256: b.Target.FileSHA256}
	patch.Target.Function = "Withdraw"
	patch.Target.AssignmentLHS = "w.Balance"
	fresh, err := NewCandidateCatalog(b.ID, b.Target.FileSHA256)
	if err != nil {
		t.Fatal(err)
	}
	cB, err := fresh.Register(patch, strings.Repeat("c", 64), "Other operation")
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Seal(); err != nil {
		t.Fatal(err)
	}
	_ = catalogB
	if err := b.SelectCandidate(fresh, cB.ID); err != nil {
		t.Fatal(err)
	}
	if err := b.MarkValidated(r); err == nil || b.State != Proposed {
		t.Fatal("report replayed across candidates")
	}
	r.CandidateID = b.CandidateID
	r.CandidateDigest = b.CandidateDigest
	if err := b.MarkValidated(r); err == nil {
		t.Fatal("output hash mismatch accepted")
	}
	r.CandidateOutputSHA256 = b.CandidateOutputSHA256
	if err := b.MarkValidated(r); err != nil {
		t.Fatal(err)
	}
}
func TestRequiredGatePolicy(t *testing.T) {
	tx, catalog, c := fixture(t)
	if err := tx.SelectCandidate(catalog, c.ID); err != nil {
		t.Fatal(err)
	}
	r := reportFor(tx)
	r.Gates = r.Gates[:4]
	if err := tx.MarkValidated(r); err == nil {
		t.Fatal("absent test accepted")
	}
	r = reportFor(tx)
	r.Gates[0].Status = Skipped
	if err := tx.MarkValidated(r); err == nil {
		t.Fatal("skipped parse accepted")
	}
	r = reportFor(tx)
	r.Gates = append(r.Gates, r.Gates[0])
	if err := tx.MarkValidated(r); err == nil {
		t.Fatal("duplicate gate accepted")
	}
	r = reportFor(tx)
	r.PolicySHA256 = ""
	if err := tx.MarkValidated(r); err == nil {
		t.Fatal("missing gate policy accepted")
	}
}
func TestNoHashOrUnknownIntent(t *testing.T) {
	tx, _, _ := fixture(t)
	tx.Target.FileSHA256 = ""
	if _, err := NewTransaction(tx.ID, tx.Target, tx.Intent); err == nil {
		t.Fatal("hash must be required")
	}
	tx.Target.FileSHA256 = strings.Repeat("a", 64)
	tx.Intent.Kind = "unknown"
	if _, err := NewTransaction(tx.ID, tx.Target, tx.Intent); err == nil {
		t.Fatal("unknown intent accepted")
	}
}

func TestCatalogueSealedBeforeResolveAndNoLaterMutation(t *testing.T) {
	tx, _, _ := fixture(t)
	cat, err := NewCandidateCatalog(tx.ID, tx.Target.FileSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := cat.Resolve("mut_unknown", tx.ID, tx.Target.FileSHA256); err == nil {
		t.Fatal("unsealed catalogue resolved")
	}
	if err := cat.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := cat.Seal(); err == nil {
		t.Fatal("double seal accepted")
	}
	patch := engine.Patch{Action: "replace_binary_operator", ExpectedFileSHA256: tx.Target.FileSHA256}
	if _, err := cat.Register(patch, strings.Repeat("f", 64), "late"); err == nil {
		t.Fatal("sealed catalogue accepted a patch")
	}
}
