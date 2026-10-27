package recon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kbelludoo/goai/internal/agentproto"
	"github.com/kbelludoo/goai/internal/engine"
)

func fixture(t *testing.T, source string) (string, []byte, agentproto.RecognitionRequest) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wallet.go")
	src := []byte(source)
	if err := os.WriteFile(path, src, 0644); err != nil {
		t.Fatal(err)
	}
	return path, src, agentproto.RecognitionRequest{
		TransactionID: "tx-wallet", Intent: agentproto.Intent{Kind: agentproto.FixArithmeticLogic},
		Selector: agentproto.SemanticSelector{File: path, Declaration: "Withdraw", AssignmentLHS: "w.Balance", MatchPolicy: "exactly_one", FileSHA256: engine.SHA(src)},
	}
}
func TestDiscoverBoundedCandidateAndNoWrite(t *testing.T) {
	path, src, req := fixture(t, `package wallet
 type Wallet struct{ Balance int }
 func (w *Wallet) Withdraw(amount int) { w.Balance = w.Balance + amount }`)
	catalog, err := Discover(path, src, req)
	if err != nil {
		t.Fatal(err)
	}
	menu := catalog.Response()
	if len(menu.Candidates) != 1 {
		t.Fatalf("expected one candidate: %+v", menu)
	}
	serialized, err := json.Marshal(menu)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serialized), "ast_patch") {
		t.Fatal("discovery published full patch to AI")
	}
	c, patch, err := catalog.Resolve(menu.Candidates[0].ID, req.TransactionID, engine.SHA(src))
	if err != nil {
		t.Fatal(err)
	}
	if c.Digest == "" || patch.NewOperator != "-" {
		t.Fatal("wrong candidate")
	}
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(disk) != string(src) {
		t.Fatal("discovery modified disk")
	}
	result := engine.Apply(path, src, patch)
	if !result.OK || !strings.Contains(result.UpdatedSource, "w.Balance - amount") {
		t.Fatalf("unusable patch: %+v", result)
	}
}
func TestRejectStaleAndUnknownIntent(t *testing.T) {
	path, src, req := fixture(t, `package wallet
 type Wallet struct{ Balance int }
 func (w *Wallet) Withdraw(amount int) { w.Balance = w.Balance + amount }`)
	req.Selector.FileSHA256 = strings.Repeat("0", 64)
	if _, err := Discover(path, src, req); err == nil {
		t.Fatal("stale selector accepted")
	}
	req.Selector.FileSHA256 = engine.SHA(src)
	req.Intent.Kind = "invalid"
	if _, err := Discover(path, src, req); err == nil {
		t.Fatal("invalid intent accepted")
	}
}
func TestAmbiguousAssignmentsProduceNoCandidate(t *testing.T) {
	path, src, req := fixture(t, `package wallet
 type Wallet struct{ Balance int }
 func (w *Wallet) Withdraw(amount int) { w.Balance = w.Balance + amount; w.Balance = w.Balance + amount }`)
	catalog, err := Discover(path, src, req)
	if err != nil {
		t.Fatal(err)
	}
	menu := catalog.Response()
	if len(menu.Candidates) != 0 || len(menu.Diagnostics) == 0 {
		t.Fatalf("ambiguous operation offered: %+v", menu)
	}
}
func TestReceiverQualifiedSelectorRejected(t *testing.T) {
	path, src, req := fixture(t, `package wallet
 type Wallet struct{ Balance int }
 func (w *Wallet) Withdraw(amount int) { w.Balance = w.Balance + amount }`)
	req.Selector.Declaration = "(*Wallet).Withdraw"
	if _, err := Discover(path, src, req); err == nil {
		t.Fatal("unimplemented receiver symbol should fail")
	}
}
func TestSameBasenameDifferentDirectoryRejected(t *testing.T) {
	path, src, req := fixture(t, `package wallet
 type Wallet struct{ Balance int }
 func (w *Wallet) Withdraw(amount int) { w.Balance = w.Balance + amount }`)
	req.Selector.File = filepath.Join(filepath.Dir(path), "elsewhere", "wallet.go")
	if _, err := Discover(path, src, req); err == nil {
		t.Fatal("basename collision accepted")
	}
}
func TestMaxCandidateCapFlag(t *testing.T) {
	path, src, req := fixture(t, `package wallet
 type Wallet struct{ Balance int; Fee int }
 func (w *Wallet) Withdraw(amount int) { w.Balance = w.Balance + amount; w.Fee = w.Fee - amount }`)
	req.Selector.AssignmentLHS = ""
	req.MaxCandidates = 1
	catalog, err := Discover(path, src, req)
	if err != nil {
		t.Fatal(err)
	}
	menu := catalog.Response()
	if len(menu.Candidates) != 1 || !menu.Capped {
		t.Fatalf("expected bounded menu with cap indicator: %+v", menu)
	}
}
