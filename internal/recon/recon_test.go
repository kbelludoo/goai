package recon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kbelludoo/goai/internal/agentproto"
	"github.com/kbelludoo/goai/internal/engine"
)

func fixture(t *testing.T, source string) (string, []byte, agentproto.RecognitionRequest) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.go")
	src := []byte(source)
	if err := os.WriteFile(path, src, 0644); err != nil {
		t.Fatal(err)
	}
	return path, src, agentproto.RecognitionRequest{
		TransactionID: "tx-wallet", Intent: agentproto.Intent{Kind: agentproto.FixArithmeticLogic},
		Selector: agentproto.SemanticSelector{
			File: "wallet.go", Declaration: "Withdraw", AssignmentLHS: "w.Balance", MatchPolicy: "exactly_one", FileSHA256: engine.SHA(src),
		},
	}
}

func TestDiscoverBoundedCandidateAndNoWrite(t *testing.T) {
	path, src, req := fixture(t, `package wallet
    type Wallet struct{ Balance int }
    func (w *Wallet) Withdraw(amount int) { w.Balance = w.Balance + amount }`)
	res, err := Discover(path, src, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Candidates) != 1 {
		t.Fatalf("want one candidate: %+v", res)
	}
	c, err := res.Choose(res.Candidates[0].ID, engine.SHA(src))
	if err != nil {
		t.Fatal(err)
	}
	if c.Patch.NewOperator != "-" {
		t.Fatalf("unexpected candidate: %+v", c)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != string(src) {
		t.Fatal("discovery edited original")
	}
	r := engine.Apply(path, src, c.Patch)
	if !r.OK || !strings.Contains(r.UpdatedSource, "w.Balance - amount") {
		t.Fatalf("candidate not applicable: %+v", r)
	}
}

func TestRejectStaleAndNoGuessing(t *testing.T) {
	path, src, req := fixture(t, `package wallet
    type Wallet struct{ Balance int }
    func (w *Wallet) Withdraw(amount int) { w.Balance = w.Balance + amount }`)
	req.Selector.FileSHA256 = strings.Repeat("0", 64)
	if _, err := Discover(path, src, req); err == nil {
		t.Fatal("stale selector accepted")
	}
	req.Selector.FileSHA256 = engine.SHA(src)
	req.Intent.Kind = "invented"
	if _, err := Discover(path, src, req); err == nil {
		t.Fatal("unknown intent accepted")
	}
}

func TestAmbiguousAssignmentsProduceNoActionableCandidate(t *testing.T) {
	path, src, req := fixture(t, `package wallet
    type Wallet struct{ Balance int }
    func (w *Wallet) Withdraw(amount int) { w.Balance = w.Balance + amount; w.Balance = w.Balance + amount }`)
	res, err := Discover(path, src, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Candidates) != 0 || len(res.Diagnostics) == 0 {
		t.Fatalf("should reject ambiguous candidate: %+v", res)
	}
}

func TestUnknownReceiverQualifiedSelectorRejected(t *testing.T) {
	path, src, req := fixture(t, `package wallet
    type Wallet struct{ Balance int }
    func (w *Wallet) Withdraw(amount int) { w.Balance = w.Balance + amount }`)
	req.Selector.Declaration = "(*Wallet).Withdraw"
	if _, err := Discover(path, src, req); err == nil {
		t.Fatal("receiver qualified support must not be claimed")
	}
}
