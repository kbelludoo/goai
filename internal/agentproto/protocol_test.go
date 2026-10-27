package agentproto

import (
	"strings"
	"testing"
)

func makeTx(t *testing.T) Transaction {
	t.Helper()
	tx, err := NewTransaction("tx-001", SemanticSelector{
		File: "wallet.go", Declaration: "Withdraw", MatchPolicy: "exactly_one",
		FileSHA256: strings.Repeat("a", 64),
	}, Intent{Kind: FixArithmeticLogic, Description: "withdrawal decreases balance"})
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestTransactionLifecycle(t *testing.T) {
	tx := makeTx(t)
	if err := tx.Transition(Committed); err == nil {
		t.Fatal("must not skip validation")
	}
	c := Candidate{ID: "candidate-1", TransactionID: tx.ID, SourceSHA256: tx.Target.FileSHA256}
	if err := tx.SelectCandidate(c); err != nil {
		t.Fatal(err)
	}
	if err := tx.Transition(Validated); err == nil {
		t.Fatal("must not validate without evidence")
	}
	r := ValidationReport{RevisionSHA256: tx.Target.FileSHA256}
	for _, name := range []GateName{ParseGate, TypesGate, VetGate, BuildGate, TestsGate} {
		r.Gates = append(r.Gates, GateResult{Name: name, Status: Pass})
	}
	if err := tx.MarkValidated(r); err != nil {
		t.Fatal(err)
	}
	if err := tx.Transition(Committed); err != nil {
		t.Fatal(err)
	}
	if err := tx.Transition(Proposed); err == nil {
		t.Fatal("committed must be terminal")
	}
}

func TestRejectedTerminal(t *testing.T) {
	tx := makeTx(t)
	if err := tx.Transition(Rejected); err != nil {
		t.Fatal(err)
	}
	if err := tx.Transition(Pending); err == nil {
		t.Fatal("rejected must be terminal")
	}
}

func TestNewTransactionRejectsMissingRevision(t *testing.T) {
	_, err := NewTransaction("tx-001", SemanticSelector{
		File: "wallet.go", Declaration: "Withdraw", MatchPolicy: "exactly_one",
	}, Intent{Kind: FixArithmeticLogic})
	if err == nil {
		t.Fatal("expected hash requirement")
	}
}

func TestRequiredValidationGates(t *testing.T) {
	revision := strings.Repeat("b", 64)
	r := ValidationReport{RevisionSHA256: revision, Gates: []GateResult{
		{Name: ParseGate, Status: Pass}, {Name: TypesGate, Status: Pass}, {Name: TestsGate, Status: NotRun},
	}}
	if err := r.RequirePass(revision, ParseGate, TypesGate, TestsGate); err == nil {
		t.Fatal("unrun test must not count as pass")
	}
	r.Gates[2].Status = Pass
	if err := r.RequirePass(revision, ParseGate, TypesGate, TestsGate); err != nil {
		t.Fatal(err)
	}
	if err := r.RequirePass(strings.Repeat("c", 64), ParseGate); err == nil {
		t.Fatal("stale report accepted")
	}
	r.Gates = append(r.Gates, GateResult{Name: TypesGate, Status: Pass})
	if err := r.RequirePass(revision, ParseGate); err == nil {
		t.Fatal("duplicate gate accepted")
	}
}

func TestCandidateChoiceChecksVersionAndUniqueness(t *testing.T) {
	rev := strings.Repeat("d", 64)
	r := RecognitionResponse{TransactionID: "tx", SourceSHA256: rev,
		Candidates: []Candidate{{ID: "c1", TransactionID: "tx", SourceSHA256: rev}}}
	if _, err := r.Choose("c1", rev); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Choose("c1", strings.Repeat("e", 64)); err == nil {
		t.Fatal("stale response accepted")
	}
	if _, err := r.Choose("unknown", rev); err == nil {
		t.Fatal("unknown candidate accepted")
	}
	r.Candidates = append(r.Candidates, r.Candidates[0])
	if _, err := r.Choose("c1", rev); err == nil {
		t.Fatal("duplicate candidate accepted")
	}
}

func TestMarkValidatedFailsIfTestsAbsent(t *testing.T) {
	tx := makeTx(t)
	if err := tx.SelectCandidate(Candidate{ID: "mut", TransactionID: tx.ID, SourceSHA256: tx.Target.FileSHA256}); err != nil {
		t.Fatal(err)
	}
	r := ValidationReport{RevisionSHA256: tx.Target.FileSHA256, Gates: []GateResult{
		{Name: ParseGate, Status: Pass}, {Name: TypesGate, Status: Pass}, {Name: VetGate, Status: Pass}, {Name: BuildGate, Status: Pass},
	}}
	if err := tx.MarkValidated(r); err == nil || tx.State != Proposed {
		t.Fatal("must remain unvalidated when tests are absent")
	}
}
