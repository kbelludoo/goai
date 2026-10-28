package txmanager

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kbelludoo/goai/internal/agentproto"
	"github.com/kbelludoo/goai/internal/engine"
)

type stubOracle struct{ fail error }

func (s stubOracle) Validate(ctx context.Context, w validationWork) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if engine.SHA(w.candidateSource) != w.candidateOutputSHA256 {
		return errors.New("invalid candidate output")
	}
	return s.fail
}

func setup(t *testing.T, withOracle bool) (*Manager, agentproto.RecognitionRequest, string, []byte) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.go")
	code := []byte("package wallet\ntype Wallet struct{ Balance int }\nfunc (w *Wallet) Withdraw(amount int) { w.Balance = w.Balance + amount }\n")
	if err := os.WriteFile(path, code, 0600); err != nil {
		t.Fatal(err)
	}
	req := agentproto.RecognitionRequest{TransactionID: "tx-1", Selector: agentproto.SemanticSelector{File: path, Declaration: "Withdraw", AssignmentLHS: "w.Balance", FileSHA256: engine.SHA(code), MatchPolicy: "exactly_one"}, Intent: agentproto.Intent{Kind: agentproto.FixArithmeticLogic}}
	var m *Manager
	var err error
	if withOracle {
		m, err = newManager(time.Minute, stubOracle{})
	} else {
		m, err = NewManager(time.Minute)
	}
	if err != nil {
		t.Fatal(err)
	}
	return m, req, path, code
}
func beginChoose(t *testing.T, m *Manager, req agentproto.RecognitionRequest) Menu {
	t.Helper()
	menu, err := m.Begin(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(menu.Catalog.Candidates) != 1 {
		t.Fatalf("need exactly one candidate; got %d", len(menu.Catalog.Candidates))
	}
	if _, err = m.Choose(req.TransactionID, menu.ReconToken, menu.Catalog.Candidates[0].ID); err != nil {
		t.Fatal(err)
	}
	return menu
}
func TestNoOracleCannotApproveOrCommit(t *testing.T) {
	m, req, path, before := setup(t, false)
	menu := beginChoose(t, m, req)
	_, err := m.Validate(context.Background(), req.TransactionID, menu.ReconToken)
	if !errors.Is(err, ErrValidatorUnavailable) {
		t.Fatalf("fail-closed validation wanted; got %v", err)
	}
	if _, err = m.Commit(req.TransactionID, strings.Repeat("f", 64)); !errors.Is(err, ErrState) {
		t.Fatalf("fake commit should fail: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(before) {
		t.Fatal("untrusted agent modified disk")
	}
}
func TestFabricatedIDAndReconTokenRejected(t *testing.T) {
	m, req, _, _ := setup(t, false)
	menu, err := m.Begin(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Choose(req.TransactionID, strings.Repeat("0", 64), menu.Catalog.Candidates[0].ID); !errors.Is(err, ErrToken) {
		t.Fatalf("invalid token accepted: %v", err)
	}
	if _, err = m.Choose(req.TransactionID, menu.ReconToken, "mut_forged"); err == nil {
		t.Fatal("unissued candidate accepted")
	}
	// Response is a mutable copy. Corrupting it does not change the registry.
	menu.Catalog.Candidates[0].ID = "mut_forged"
	menu.Catalog.Candidates[0].Description = "a different patch"
	if _, err = m.Choose(req.TransactionID, menu.ReconToken, "mut_forged"); err == nil {
		t.Fatal("tampered menu could pick a candidate")
	}
}
func TestOneTimeCommitTokenAndAudit(t *testing.T) {
	m, req, path, _ := setup(t, true)
	menu := beginChoose(t, m, req)
	if _, err := m.Commit(req.TransactionID, strings.Repeat("1", 64)); !errors.Is(err, ErrState) {
		t.Fatalf("approved without validation: %v", err)
	}
	receipt, err := m.Validate(context.Background(), req.TransactionID, menu.ReconToken)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.CommitToken == "" || receipt.State != Approved {
		t.Fatal("missing approval capability")
	}
	if _, err = m.Commit(req.TransactionID, strings.Repeat("b", 64)); !errors.Is(err, ErrToken) {
		t.Fatalf("forged token succeeded: %v", err)
	}
	if _, err = m.Commit(req.TransactionID, receipt.CommitToken); err != nil {
		t.Fatal(err)
	}
	src, _ := os.ReadFile(path)
	if !strings.Contains(string(src), "w.Balance - amount") {
		t.Fatalf("wrong output: %s", src)
	}
	if _, err = m.Commit(req.TransactionID, receipt.CommitToken); !errors.Is(err, ErrState) {
		t.Fatalf("replay should fail: %v", err)
	}
	events := m.AuditSnapshot()
	if len(events) != 5 {
		t.Fatalf("got %d audit events, want 5", len(events))
	}
	prior := ""
	for i, e := range events {
		if e.PreviousSHA256 != prior {
			t.Fatal("broken hash chain")
		}
		data := fmt.Sprintf("%d\x00%s\x00%s\x00%s\x00%s", e.Sequence, e.TransactionID, e.Event, e.CandidateDigest, e.PreviousSHA256)
		sum := sha256.Sum256([]byte(data))
		if e.SHA256 != hex.EncodeToString(sum[:]) || int(e.Sequence) != i+1 {
			t.Fatal("invalid audit digest")
		}
		prior = e.SHA256
	}
	events[0].Event = "fake"
	if m.AuditSnapshot()[0].Event == "fake" {
		t.Fatal("audit returned mutable alias")
	}
}
func TestStaleSourceCannotCommit(t *testing.T) {
	m, req, path, _ := setup(t, true)
	menu := beginChoose(t, m, req)
	approval, err := m.Validate(context.Background(), req.TransactionID, menu.ReconToken)
	if err != nil {
		t.Fatal(err)
	}
	replacement := []byte("package wallet\nfunc Different() {}\n")
	if err := os.WriteFile(path, replacement, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Commit(req.TransactionID, approval.CommitToken); !errors.Is(err, ErrStale) {
		t.Fatalf("expected conflict: %v", err)
	}
	b, _ := os.ReadFile(path)
	if string(b) != string(replacement) {
		t.Fatal("wrote across a source conflict")
	}
	if _, err = m.Commit(req.TransactionID, approval.CommitToken); !errors.Is(err, ErrState) {
		t.Fatalf("stale token replayed: %v", err)
	}
}
func TestScopeLockedAndReleasedOnReject(t *testing.T) {
	m, req, _, _ := setup(t, false)
	menu, err := m.Begin(req)
	if err != nil {
		t.Fatal(err)
	}
	second := req
	second.TransactionID = "tx-2"
	if _, err = m.Begin(second); !errors.Is(err, ErrLocked) {
		t.Fatalf("file lock bypassed: %v", err)
	}
	if err := m.Reject(req.TransactionID, strings.Repeat("1", 64)); !errors.Is(err, ErrToken) {
		t.Fatalf("invalid cancel token accepted: %v", err)
	}
	if err := m.Reject(req.TransactionID, menu.ReconToken); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Begin(second); err != nil {
		t.Fatalf("lock not released: %v", err)
	}
}
func TestExpiryReleasesScopeOnGet(t *testing.T) {
	m, req, _, _ := setup(t, false)
	instant := time.Now()
	m.now = func() time.Time { return instant }
	menu, err := m.Begin(req)
	if err != nil {
		t.Fatal(err)
	}
	instant = instant.Add(2 * time.Minute)
	if _, err = m.Choose(req.TransactionID, menu.ReconToken, menu.Catalog.Candidates[0].ID); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired token accepted: %v", err)
	}
	second := req
	second.TransactionID = "tx-2"
	if _, err := m.Begin(second); err != nil {
		t.Fatalf("expired scope still locked: %v", err)
	}
}
func TestFailedOracleRejectsWithoutToken(t *testing.T) {
	m, req, path, before := setup(t, true)
	m.oracle = stubOracle{fail: errors.New("failed contracts")}
	menu := beginChoose(t, m, req)
	if receipt, err := m.Validate(context.Background(), req.TransactionID, menu.ReconToken); err == nil || receipt.CommitToken != "" {
		t.Fatal("failed oracle could approve")
	}
	if _, err := m.Commit(req.TransactionID, strings.Repeat("0", 64)); !errors.Is(err, ErrState) {
		t.Fatalf("failed oracle permitted commit: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(before) {
		t.Fatal("changed disk after failure")
	}
}
func TestSimultaneousCommitTokenReplay(t *testing.T) {
	m, req, _, _ := setup(t, true)
	menu := beginChoose(t, m, req)
	approval, err := m.Validate(context.Background(), req.TransactionID, menu.ReconToken)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	ok := make(chan struct{}, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.Commit(req.TransactionID, approval.CommitToken); err == nil {
				ok <- struct{}{}
			}
		}()
	}
	wg.Wait()
	close(ok)
	if len(ok) != 1 {
		t.Fatalf("%d commits passed with same token, want exactly one", len(ok))
	}
}

func TestBeginReclaimsExpiredScopeWithoutOwnerCall(t *testing.T) {
	m, req, _, _ := setup(t, false)
	instant := time.Now()
	m.now = func() time.Time { return instant }
	if _, err := m.Begin(req); err != nil {
		t.Fatal(err)
	}
	instant = instant.Add(2 * time.Minute)
	other := req
	other.TransactionID = "tx-2"
	if _, err := m.Begin(other); err != nil {
		t.Fatalf("begin must reclaim expired lock: %v", err)
	}
}
func TestCanceledValidationNeverApproves(t *testing.T) {
	m, req, _, _ := setup(t, true)
	menu := beginChoose(t, m, req)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if receipt, err := m.Validate(ctx, req.TransactionID, menu.ReconToken); err == nil || receipt.CommitToken != "" {
		t.Fatal("canceled validation generated approval token")
	}
}

// gatedOracle suspends one source file's validation. It deliberately may
// ignore context cancellation to verify that the manager retains the file
// reservation until the real backend has *returned*.
type gatedOracle struct {
	blockPath string
	entered   chan struct{}
	release   chan struct{}
	ignoreCtx bool
}

func (o *gatedOracle) Validate(ctx context.Context, work validationWork) error {
	if engine.SHA(work.candidateSource) != work.candidateOutputSHA256 {
		return errors.New("candidate changed")
	}
	if work.sourceFile != o.blockPath {
		return ctx.Err()
	}
	select {
	case o.entered <- struct{}{}:
	default:
	}
	if o.ignoreCtx {
		<-o.release
		return nil
	}
	select {
	case <-o.release:
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

type validationOutcome struct {
	receipt Receipt
	err     error
}

func awaitValidation(t *testing.T, results <-chan validationOutcome) validationOutcome {
	t.Helper()
	select {
	case got := <-results:
		return got
	case <-time.After(3 * time.Second):
		t.Fatal("validation did not finish")
		return validationOutcome{}
	}
}

func awaitEntry(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("oracle was not entered")
	}
}

func independentRequest(t *testing.T, req agentproto.RecognitionRequest, src []byte) agentproto.RecognitionRequest {
	t.Helper()
	newPath := filepath.Join(t.TempDir(), "wallet.go")
	if err := os.WriteFile(newPath, src, 0600); err != nil {
		t.Fatal(err)
	}
	req.TransactionID = "tx-second"
	req.Selector.File = newPath
	return req
}

func TestIndependentFilesValidateWithoutGlobalLock(t *testing.T) {
	m, req, path, src := setup(t, true)
	oracle := &gatedOracle{blockPath: path, entered: make(chan struct{}, 1), release: make(chan struct{})}
	m.oracle = oracle // test-only injection inside this trusted package
	menuA := beginChoose(t, m, req)
	reqB := independentRequest(t, req, src)

	resultA := make(chan validationOutcome, 1)
	go func() {
		r, err := m.Validate(context.Background(), req.TransactionID, menuA.ReconToken)
		resultA <- validationOutcome{r, err}
	}()
	awaitEntry(t, oracle.entered)
	// Begin/Discover and Choose must also work on B while A validates.
	menuB := beginChoose(t, m, reqB)

	resultB := make(chan validationOutcome, 1)
	go func() {
		r, err := m.Validate(context.Background(), reqB.TransactionID, menuB.ReconToken)
		resultB <- validationOutcome{r, err}
	}()
	// B must finish before A's validator is released. This is a controlled
	// concurrency proof rather than an unreliable sub-100ms timing assertion.
	gotB := awaitValidation(t, resultB)
	if gotB.err != nil || gotB.receipt.State != Approved {
		t.Fatalf("independent validation was blocked/rejected: %+v", gotB)
	}
	otherA := req
	otherA.TransactionID = "tx-conflict"
	if _, err := m.Begin(otherA); !errors.Is(err, ErrLocked) {
		t.Fatalf("same file must be reserved while A validates: %v", err)
	}
	close(oracle.release)
	gotA := awaitValidation(t, resultA)
	if gotA.err != nil || gotA.receipt.State != Approved {
		t.Fatalf("A unexpectedly failed after unblock: %+v", gotA)
	}
	if _, err := m.Begin(otherA); !errors.Is(err, ErrLocked) {
		t.Fatalf("scope must remain reserved after approval, until commit/reject: %v", err)
	}
	if err := m.Reject(req.TransactionID, menuA.ReconToken); err != nil {
		t.Fatal(err)
	}
	if err := m.Reject(reqB.TransactionID, menuB.ReconToken); err != nil {
		t.Fatal(err)
	}
}

func TestRejectDuringUncooperativeValidationKeepsLock(t *testing.T) {
	m, req, path, _ := setup(t, true)
	oracle := &gatedOracle{blockPath: path, entered: make(chan struct{}, 1), release: make(chan struct{}), ignoreCtx: true}
	m.oracle = oracle
	menu := beginChoose(t, m, req)
	out := make(chan validationOutcome, 1)
	go func() {
		r, err := m.Validate(context.Background(), req.TransactionID, menu.ReconToken)
		out <- validationOutcome{r, err}
	}()
	awaitEntry(t, oracle.entered)
	if _, err := m.Validate(context.Background(), req.TransactionID, menu.ReconToken); !errors.Is(err, ErrState) {
		t.Fatalf("duplicate validation started: %v", err)
	}
	if err := m.Reject(req.TransactionID, menu.ReconToken); err != nil {
		t.Fatal(err)
	}
	second := req
	second.TransactionID = "tx-second"
	if _, err := m.Begin(second); !errors.Is(err, ErrLocked) {
		t.Fatalf("cancel released file before validator stopped: %v", err)
	}
	close(oracle.release)
	got := awaitValidation(t, out)
	if !errors.Is(got.err, context.Canceled) || got.receipt.CommitToken != "" {
		t.Fatalf("canceled validator still approved: %+v", got)
	}
	if _, err := m.Begin(second); err != nil {
		t.Fatalf("canceled validator leaked scope: %v", err)
	}
}

func TestExpiredValidationDoesNotFreeRunningScope(t *testing.T) {
	m, req, path, _ := setup(t, true)
	clock := time.Now()
	var nowNano atomic.Int64
	nowNano.Store(clock.UnixNano())
	m.now = func() time.Time { return time.Unix(0, nowNano.Load()) }
	oracle := &gatedOracle{blockPath: path, entered: make(chan struct{}, 1), release: make(chan struct{}), ignoreCtx: true}
	m.oracle = oracle
	menu := beginChoose(t, m, req)
	out := make(chan validationOutcome, 1)
	go func() {
		r, err := m.Validate(context.Background(), req.TransactionID, menu.ReconToken)
		out <- validationOutcome{r, err}
	}()
	awaitEntry(t, oracle.entered)
	nowNano.Store(clock.Add(2 * time.Minute).UnixNano())
	second := req
	second.TransactionID = "tx-new-after-expiration"
	if _, err := m.Begin(second); !errors.Is(err, ErrLocked) {
		t.Fatalf("expiry prematurely released running scope: %v", err)
	}
	close(oracle.release)
	got := awaitValidation(t, out)
	if got.err == nil || got.receipt.CommitToken != "" {
		t.Fatalf("expired validation approved: %+v", got)
	}
	if _, err := m.Begin(second); err != nil {
		t.Fatalf("expired validation leaked scope: %v", err)
	}
}

func TestSlowValidationRejectsExternalFileChange(t *testing.T) {
	m, req, path, _ := setup(t, true)
	oracle := &gatedOracle{blockPath: path, entered: make(chan struct{}, 1), release: make(chan struct{})}
	m.oracle = oracle
	menu := beginChoose(t, m, req)
	out := make(chan validationOutcome, 1)
	go func() {
		r, err := m.Validate(context.Background(), req.TransactionID, menu.ReconToken)
		out <- validationOutcome{r, err}
	}()
	awaitEntry(t, oracle.entered)
	replacement := []byte("package wallet\nfunc Replaced() {}\n")
	if err := os.WriteFile(path, replacement, 0600); err != nil {
		t.Fatal(err)
	}
	close(oracle.release)
	got := awaitValidation(t, out)
	if !errors.Is(got.err, ErrStale) || got.receipt.CommitToken != "" {
		t.Fatalf("external write should reject validation: %+v", got)
	}
	src, _ := os.ReadFile(path)
	if string(src) != string(replacement) {
		t.Fatalf("external file unexpectedly overwritten: %q", src)
	}
}

func TestContextCancellationDuringValidationReleasesLock(t *testing.T) {
	m, req, path, _ := setup(t, true)
	oracle := &gatedOracle{blockPath: path, entered: make(chan struct{}, 1), release: make(chan struct{})}
	m.oracle = oracle
	menu := beginChoose(t, m, req)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan validationOutcome, 1)
	go func() {
		r, err := m.Validate(ctx, req.TransactionID, menu.ReconToken)
		out <- validationOutcome{r, err}
	}()
	awaitEntry(t, oracle.entered)
	cancel()
	got := awaitValidation(t, out)
	if !errors.Is(got.err, context.Canceled) || got.receipt.CommitToken != "" {
		t.Fatalf("cancel must reject without capability: %+v", got)
	}
	other := req
	other.TransactionID = "tx-next"
	if _, err := m.Begin(other); err != nil {
		t.Fatalf("scope not released after validator stopped: %v", err)
	}
}
