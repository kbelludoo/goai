// Package agentproto defines GoAI's draft agent-facing protocol.
// All data received from agents (including validation reports) is untrusted.
// This package does NOT provide sandbox isolation or validation attestation.
package agentproto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/kbelludoo/goai/internal/engine"
)

const ProtocolVersion = "goai.v0.2-draft"

type TxState string

const (
	Pending   TxState = "pending"
	Proposed  TxState = "proposed"
	Validated TxState = "validated" // Advisory state only until a trusted executor exists.
	Rejected  TxState = "rejected"
	Committed TxState = "committed" // No source/Git commit is performed by this package.
)

type SemanticSelector struct {
	Package       string `json:"package,omitempty"`
	File          string `json:"file"`
	Declaration   string `json:"declaration"`
	AssignmentLHS string `json:"assignment_lhs,omitempty"`
	FileSHA256    string `json:"file_sha256"`
	MatchPolicy   string `json:"match_policy"`
}

type IntentKind string

const FixArithmeticLogic IntentKind = "fix_arithmetic_logic"

type Intent struct {
	Kind        IntentKind `json:"kind"`
	Description string     `json:"description,omitempty"`
}

type Contract struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Reference string `json:"reference"`
}

type Transaction struct {
	ID                    string           `json:"id"`
	Protocol              string           `json:"protocol"`
	Target                SemanticSelector `json:"target"`
	Intent                Intent           `json:"intent"`
	Preconditions         []Contract       `json:"preconditions,omitempty"`
	Postconditions        []Contract       `json:"postconditions,omitempty"`
	CandidateID           string           `json:"candidate_id,omitempty"`
	CandidateDigest       string           `json:"candidate_digest,omitempty"`
	CandidateOutputSHA256 string           `json:"candidate_output_sha256,omitempty"`
	State                 TxState          `json:"state"`
}

func IsSHA256(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func NewTransaction(id string, selector SemanticSelector, intent Intent) (Transaction, error) {
	if id == "" || selector.File == "" || selector.Declaration == "" || selector.MatchPolicy != "exactly_one" || !IsSHA256(selector.FileSHA256) {
		return Transaction{}, errors.New("transaction requires ID, file, declaration, exactly_one and 64-digit file SHA256")
	}
	if intent.Kind != FixArithmeticLogic {
		return Transaction{}, fmt.Errorf("unsupported intent %q", intent.Kind)
	}
	return Transaction{ID: id, Protocol: ProtocolVersion, Target: selector, Intent: intent, State: Pending}, nil
}
func (tx *Transaction) Transition(next TxState) error {
	if tx == nil {
		return errors.New("nil transaction")
	}
	allowed := map[TxState][]TxState{Pending: {Proposed, Rejected}, Proposed: {Rejected}, Validated: {Committed, Rejected}}
	if next == Proposed && (tx.CandidateID == "" || !IsSHA256(tx.CandidateDigest) || !IsSHA256(tx.CandidateOutputSHA256)) {
		return errors.New("cannot propose without a bound candidate and output digest")
	}
	for _, v := range allowed[tx.State] {
		if v == next {
			tx.State = next
			return nil
		}
	}
	return fmt.Errorf("invalid transaction transition %q -> %q", tx.State, next)
}

type Candidate struct {
	ID            string `json:"id"`
	TransactionID string `json:"tx_id"`
	SourceSHA256  string `json:"source_sha256"`
	Digest        string `json:"digest"`
	OutputSHA256  string `json:"output_sha256"`
	Description   string `json:"summary"`
}

// candidateRecord stays in process, and never serializes into the agent's menu.
type candidateRecord struct {
	candidate Candidate
	patch     engine.Patch
}

// CandidateCatalog owns copies of the proposed patches. Agent requests can
// only choose an ID; never accept serialized catalogues from untrusted clients.
type CandidateCatalog struct {
	mu            sync.RWMutex
	sealed        bool
	transactionID string
	sourceSHA256  string
	entries       map[string]candidateRecord
	order         []string
	diagnostics   []engine.Diagnostic
	capped        bool
}

func NewCandidateCatalog(txID, sourceSHA256 string) (*CandidateCatalog, error) {
	if txID == "" || !IsSHA256(sourceSHA256) {
		return nil, errors.New("invalid catalogue transaction or revision")
	}
	return &CandidateCatalog{transactionID: txID, sourceSHA256: strings.ToLower(sourceSHA256), entries: make(map[string]candidateRecord)}, nil
}
func candidateDigest(txID, sourceHash string, patch engine.Patch, outputSHA string) (string, error) {
	b, err := json.Marshal(struct {
		TransactionID string       `json:"tx_id"`
		SourceSHA256  string       `json:"source_sha256"`
		Patch         engine.Patch `json:"patch"`
		OutputSHA256  string       `json:"output_sha256"`
	}{txID, sourceHash, patch, outputSHA})
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// Register is a trusted-local builder function, NOT an agent-facing endpoint.
// The caller must produce the patch with the local AST engine, not from JSON.
func (c *CandidateCatalog) Register(patch engine.Patch, outputSHA, description string) (Candidate, error) {
	if c == nil {
		return Candidate{}, errors.New("nil catalogue")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sealed {
		return Candidate{}, errors.New("catalogue is sealed")
	}
	if !IsSHA256(outputSHA) || !strings.EqualFold(patch.ExpectedFileSHA256, c.sourceSHA256) {
		return Candidate{}, errors.New("candidate output/source revision invalid")
	}
	digest, err := candidateDigest(c.transactionID, c.sourceSHA256, patch, strings.ToLower(outputSHA))
	if err != nil {
		return Candidate{}, err
	}
	candidate := Candidate{ID: "mut_" + digest, TransactionID: c.transactionID, SourceSHA256: c.sourceSHA256, Digest: digest, OutputSHA256: strings.ToLower(outputSHA), Description: description}
	if _, ok := c.entries[candidate.ID]; ok {
		return Candidate{}, errors.New("duplicate candidate ID")
	}
	c.entries[candidate.ID] = candidateRecord{candidate: candidate, patch: patch}
	c.order = append(c.order, candidate.ID)
	return candidate, nil
}
func (c *CandidateCatalog) AddDiagnostics(ds ...engine.Diagnostic) {
	if c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.sealed {
			c.diagnostics = append(c.diagnostics, ds...)
		}
	}
}
func (c *CandidateCatalog) SetCapped() {
	if c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.sealed {
			c.capped = true
		}
	}
}
func (c *CandidateCatalog) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Seal closes candidate discovery. Future registrations are refused, even
// when multiple goroutines discover or resolve candidates concurrently.
func (c *CandidateCatalog) Seal() error {
	if c == nil {
		return errors.New("nil catalogue")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sealed {
		return errors.New("catalogue already sealed")
	}
	c.sealed = true
	return nil
}

func (c *CandidateCatalog) Response() RecognitionResponse {
	if c == nil {
		return RecognitionResponse{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.sealed {
		return RecognitionResponse{Diagnostics: []engine.Diagnostic{{Code: "GOAI-CATALOG-002", Message: "catalogue is not sealed"}}}
	}
	out := RecognitionResponse{TransactionID: c.transactionID, SourceSHA256: c.sourceSHA256, Candidates: make([]Candidate, 0, len(c.order)), Diagnostics: append([]engine.Diagnostic{}, c.diagnostics...), Capped: c.capped}
	for _, id := range c.order {
		out.Candidates = append(out.Candidates, c.entries[id].candidate)
	}
	return out
}

// Resolve never trusts a client-provided Candidate or Patch. Its return value
// must remain on the trusted GoAI side of the protocol boundary.
func (c *CandidateCatalog) Resolve(candidateID, txID, revision string) (Candidate, engine.Patch, error) {
	if c == nil {
		return Candidate{}, engine.Patch{}, errors.New("nil catalogue")
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.sealed {
		return Candidate{}, engine.Patch{}, errors.New("catalogue is not sealed")
	}
	if c.transactionID != txID || !strings.EqualFold(c.sourceSHA256, revision) || !IsSHA256(revision) {
		return Candidate{}, engine.Patch{}, errors.New("stale or mismatched candidate catalogue")
	}
	rec, ok := c.entries[candidateID]
	if !ok {
		return Candidate{}, engine.Patch{}, errors.New("unknown or never-issued candidate ID")
	}
	digest, err := candidateDigest(c.transactionID, c.sourceSHA256, rec.patch, rec.candidate.OutputSHA256)
	if err != nil || digest != rec.candidate.Digest || rec.candidate.ID != "mut_"+digest {
		return Candidate{}, engine.Patch{}, errors.New("candidate integrity mismatch")
	}
	return rec.candidate, rec.patch, nil
}

// SelectCandidate only accepts an ID resolved from the trusted local catalog.
func (tx *Transaction) SelectCandidate(catalog *CandidateCatalog, candidateID string) error {
	if tx == nil || tx.State != Pending {
		return errors.New("candidate requires pending transaction")
	}
	if catalog == nil {
		return errors.New("nil catalogue")
	}
	c, _, err := catalog.Resolve(candidateID, tx.ID, tx.Target.FileSHA256)
	if err != nil {
		return err
	}
	tx.CandidateID = c.ID
	tx.CandidateDigest = c.Digest
	tx.CandidateOutputSHA256 = c.OutputSHA256
	return tx.Transition(Proposed)
}

type GateName string

const (
	ParseGate     GateName = "syntax"
	TypesGate     GateName = "types"
	VetGate       GateName = "vet"
	BuildGate     GateName = "build"
	TestsGate     GateName = "tests"
	ContractsGate GateName = "contracts"
)

type GateStatus string

const (
	NotRun  GateStatus = "not_run"
	Pass    GateStatus = "pass"
	Fail    GateStatus = "fail"
	Skipped GateStatus = "skipped"
)

type GateResult struct {
	Name           GateName   `json:"name"`
	Status         GateStatus `json:"status"`
	EvidenceSHA256 string     `json:"evidence_sha256,omitempty"`
	Detail         string     `json:"detail,omitempty"`
}
type ValidationReport struct {
	TransactionID         string       `json:"tx_id"`
	RevisionSHA256        string       `json:"revision_sha256"`
	CandidateID           string       `json:"candidate_id"`
	CandidateDigest       string       `json:"candidate_digest"`
	CandidateOutputSHA256 string       `json:"candidate_output_sha256"`
	PolicySHA256          string       `json:"policy_sha256"`
	Gates                 []GateResult `json:"gates"`
}

// RequireBoundPass checks *shape and identity only*, not authenticity.
// Actual Pass evidence must come from a future trusted validator, not client JSON.
func (r ValidationReport) RequireBoundPass(tx Transaction, required ...GateName) error {
	if tx.State != Proposed || r.TransactionID != tx.ID || r.CandidateID != tx.CandidateID || r.CandidateDigest != tx.CandidateDigest ||
		r.CandidateOutputSHA256 != tx.CandidateOutputSHA256 || !strings.EqualFold(r.RevisionSHA256, tx.Target.FileSHA256) ||
		!IsSHA256(r.PolicySHA256) || !IsSHA256(r.CandidateDigest) || !IsSHA256(r.CandidateOutputSHA256) {
		return errors.New("validation evidence does not bind to proposed transaction and candidate")
	}
	seen := make(map[GateName]GateStatus, len(r.Gates))
	for _, g := range r.Gates {
		if _, exists := seen[g.Name]; exists {
			return fmt.Errorf("duplicate gate %q", g.Name)
		}
		seen[g.Name] = g.Status
	}
	for _, g := range required {
		if seen[g] != Pass {
			return fmt.Errorf("required gate %q did not pass", g)
		}
	}
	return nil
}

// MarkValidated is a draft *structural check*, not a security authorization.
// Do not call with AI-authored JSON; real commits require a trusted validator.
func (tx *Transaction) MarkValidated(r ValidationReport) error {
	if tx == nil {
		return errors.New("nil transaction")
	}
	required := []GateName{ParseGate, TypesGate, VetGate, BuildGate, TestsGate}
	if len(tx.Postconditions) > 0 {
		required = append(required, ContractsGate)
	}
	if err := r.RequireBoundPass(*tx, required...); err != nil {
		return err
	}
	tx.State = Validated
	return nil
}

type RecognitionRequest struct {
	TransactionID string           `json:"tx_id"`
	Selector      SemanticSelector `json:"selector"`
	Intent        Intent           `json:"intent"`
	MaxCandidates int              `json:"max_candidates,omitempty"`
}
type RecognitionResponse struct {
	TransactionID string              `json:"tx_id"`
	SourceSHA256  string              `json:"source_sha256"`
	Candidates    []Candidate         `json:"candidates"`
	Diagnostics   []engine.Diagnostic `json:"diagnostics,omitempty"`
	Capped        bool                `json:"capped,omitempty"`
}

// A response is presentation-only. It cannot authorize edits or validation.
