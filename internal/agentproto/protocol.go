// Package agentproto defines versioned GoAI 0.2 transaction and recognition
// messages. This is a protocol draft, not an authorization or sandbox layer.
package agentproto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/kbelludoo/goai/internal/engine"
)

const ProtocolVersion = "goai.v0.2-draft"

type TxState string

const (
	Pending   TxState = "pending"
	Proposed  TxState = "proposed"
	Validated TxState = "validated"
	Rejected  TxState = "rejected"
	Committed TxState = "committed"
)

// SemanticSelector identifies intent within a versioned file. Declaration is
// a function name for the prototype. It is NOT a stable global symbol ID.
// FileSHA256 is a *precondition*, not the persistent identity of the node.
type SemanticSelector struct {
	Package       string `json:"package,omitempty"`
	File          string `json:"file"`
	Declaration   string `json:"declaration"`
	AssignmentLHS string `json:"assignment_lhs,omitempty"`
	FileSHA256    string `json:"file_sha256"`
	MatchPolicy   string `json:"match_policy"` // exactly_one, no implicit first match
}

type IntentKind string

const FixArithmeticLogic IntentKind = "fix_arithmetic_logic"

type Intent struct {
	Kind        IntentKind `json:"kind"`
	Description string     `json:"description,omitempty"` // untrusted hint, not an oracle
}

// Contract describes a requested check; it is never interpreted as a shell
// command or an executable predicate by this draft implementation.
type Contract struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"` // e.g. test, domain_invariant, file_revision
	Reference string `json:"reference"`
}

type Transaction struct {
	ID             string           `json:"id"`
	Protocol       string           `json:"protocol"`
	Target         SemanticSelector `json:"target"`
	Intent         Intent           `json:"intent"`
	Preconditions  []Contract       `json:"preconditions,omitempty"`
	Postconditions []Contract       `json:"postconditions,omitempty"`
	CandidateID    string           `json:"candidate_id,omitempty"`
	State          TxState          `json:"state"`
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

// Transition enforces lifecycle order. This is an in-process guard, not
// security: a caller can forge a JSON state or validation report.
func (tx *Transaction) Transition(next TxState) error {
	if tx == nil {
		return errors.New("nil transaction")
	}
	allowed := map[TxState][]TxState{
		Pending:   {Proposed, Rejected},
		Proposed:  {Rejected}, // validation requires an explicit gate report
		Validated: {Committed, Rejected},
	}
	if next == Proposed && tx.CandidateID == "" {
		return errors.New("cannot propose without selecting a candidate")
	}
	for _, state := range allowed[tx.State] {
		if state == next {
			tx.State = next
			return nil
		}
	}
	return fmt.Errorf("invalid transaction transition %q -> %q", tx.State, next)
}

// SelectCandidate binds the transaction to a version-scoped candidate.
// Use RecognitionResponse.Choose first to reject ambiguous candidate IDs.
func (tx *Transaction) SelectCandidate(c Candidate) error {
	if tx == nil || tx.State != Pending {
		return errors.New("candidate requires pending transaction")
	}
	if c.ID == "" || c.TransactionID != tx.ID || c.SourceSHA256 != tx.Target.FileSHA256 {
		return errors.New("candidate transaction/revision mismatch")
	}
	tx.CandidateID = c.ID
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
	RevisionSHA256 string       `json:"revision_sha256"`
	Gates          []GateResult `json:"gates"`
}

// RequirePass fails closed on absent, duplicate or non-passing required gates.
// An external trusted validator must produce the evidence: this type cannot
// prove that tests truly ran.
func (r ValidationReport) RequirePass(revision string, required ...GateName) error {
	if revision == "" || r.RevisionSHA256 != revision {
		return errors.New("validation revision mismatch")
	}
	seen := make(map[GateName]GateStatus, len(r.Gates))
	for _, gate := range r.Gates {
		if _, exists := seen[gate.Name]; exists {
			return fmt.Errorf("duplicate validation gate %q", gate.Name)
		}
		seen[gate.Name] = gate.Status
	}
	for _, name := range required {
		if seen[name] != Pass {
			return fmt.Errorf("required gate %q did not pass", name)
		}
	}
	return nil
}

// MarkValidated verifies presence of required passing gate evidence before
// the state change. Crucially, the report must be generated by a *trusted*
// executor: caller-provided JSON evidence is not a security guarantee.
func (tx *Transaction) MarkValidated(r ValidationReport) error {
	if tx == nil || tx.State != Proposed || tx.CandidateID == "" {
		return errors.New("validation requires a proposed candidate")
	}
	required := []GateName{ParseGate, TypesGate, VetGate, BuildGate, TestsGate}
	if len(tx.Postconditions) > 0 {
		required = append(required, ContractsGate)
	}
	if err := r.RequirePass(tx.Target.FileSHA256, required...); err != nil {
		return err
	}
	tx.State = Validated
	return nil
}

// RecognitionRequest is the AI's cheap query, bound to a file version.
type RecognitionRequest struct {
	TransactionID string           `json:"tx_id"`
	Selector      SemanticSelector `json:"selector"`
	Intent        Intent           `json:"intent"`
	MaxCandidates int              `json:"max_candidates,omitempty"`
}

// CandidateIDs are version-scoped, never durable semantic addresses.
type Candidate struct {
	ID            string       `json:"id"`
	TransactionID string       `json:"tx_id"`
	SourceSHA256  string       `json:"source_sha256"`
	Description   string       `json:"description"`
	Patch         engine.Patch `json:"ast_patch"`
}

type RecognitionResponse struct {
	TransactionID string              `json:"tx_id"`
	SourceSHA256  string              `json:"source_sha256"`
	Candidates    []Candidate         `json:"candidates"`
	Diagnostics   []engine.Diagnostic `json:"diagnostics,omitempty"`
}

// Choose does not apply anything; it rejects IDs from another source revision.
func (r RecognitionResponse) Choose(candidateID, actualSHA256 string) (Candidate, error) {
	if r.SourceSHA256 != actualSHA256 || !IsSHA256(actualSHA256) {
		return Candidate{}, errors.New("stale candidate catalogue")
	}
	var matches []Candidate
	for _, c := range r.Candidates {
		if c.ID == candidateID && c.TransactionID == r.TransactionID && c.SourceSHA256 == r.SourceSHA256 {
			matches = append(matches, c)
		}
	}
	if len(matches) != 1 {
		return Candidate{}, fmt.Errorf("expected exactly one candidate ID match, got %d", len(matches))
	}
	return matches[0], nil
}
