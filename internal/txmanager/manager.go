// Package txmanager is a fail-closed, in-process transaction boundary for GoAI.
// It never accepts agent-generated validation results. Its default constructor
// intentionally has NO privileged validator, so it cannot issue commit tokens.
// The synthetic oracle used by tests is not a sandbox or security attestation.
package txmanager

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kbelludoo/goai/internal/agentproto"
	"github.com/kbelludoo/goai/internal/engine"
	"github.com/kbelludoo/goai/internal/recon"
)

var (
	ErrUnknown              = errors.New("GOAI-TX-001: unknown transaction")
	ErrState                = errors.New("GOAI-TX-002: invalid transaction state")
	ErrToken                = errors.New("GOAI-TX-003: missing or invalid token")
	ErrExpired              = errors.New("GOAI-TX-004: expired transaction")
	ErrLocked               = errors.New("GOAI-TX-005: source file already locked by a transaction")
	ErrStale                = errors.New("GOAI-TX-006: source revision changed")
	ErrValidatorUnavailable = errors.New("GOAI-TX-007: trusted sandbox validator not installed; cannot approve")
)

type State string

const (
	Reconnaissance State = "reconnaissance"
	Chosen         State = "chosen"
	Approved       State = "approved"
	Rejected       State = "rejected"
	Committed      State = "committed"
)

// Menu is the public, non-authoritative response to a discovery request.
// Its token is a bearer capability and must be kept secret by the client.
type Menu struct {
	TransactionID string                         `json:"tx_id"`
	ReconToken    string                         `json:"recon_token"`
	ExpiresAt     time.Time                      `json:"expires_at"`
	Catalog       agentproto.RecognitionResponse `json:"catalog"`
}

type Receipt struct {
	TransactionID string `json:"tx_id"`
	State         State  `json:"state"`
	CommitToken   string `json:"commit_token,omitempty"`
	CandidateID   string `json:"candidate_id,omitempty"`
	OutputSHA256  string `json:"output_sha256,omitempty"`
}

// AuditEvent is a copy of an event in a process-local hash chain. Because this
// chain is neither durable nor externally anchored, it is not tamper-proof.
type AuditEvent struct {
	Sequence        uint64 `json:"sequence"`
	TransactionID   string `json:"tx_id"`
	Event           string `json:"event"`
	CandidateDigest string `json:"candidate_digest,omitempty"`
	PreviousSHA256  string `json:"previous_sha256"`
	SHA256          string `json:"sha256"`
}

// validationWork remains private to this package. A future sandbox backend must
// be installed by privileged GoAI code, NOT through any agent-facing API.
type validationWork struct {
	transactionID         string
	sourceFile            string
	sourceSHA256          string
	candidateDigest       string
	candidateOutputSHA256 string
	candidateSource       []byte
}
type trustedValidator interface {
	Validate(context.Context, validationWork) error
}

type record struct {
	state           State
	file            string
	sourceSHA256    string
	catalog         *agentproto.CandidateCatalog
	transaction     agentproto.Transaction
	reconToken      string
	commitToken     string
	expiresAt       time.Time
	candidateSource []byte
}

type Manager struct {
	mu           sync.Mutex
	transactions map[string]*record
	fileLocks    map[string]string
	audit        []AuditEvent
	ttl          time.Duration
	now          func() time.Time
	oracle       trustedValidator
}

// NewManager cannot approve or commit a change: the trusted executor has not
// been implemented. A private test constructor exercises the state machine.
func NewManager(ttl time.Duration) (*Manager, error) {
	return newManager(ttl, nil)
}

func newManager(ttl time.Duration, oracle trustedValidator) (*Manager, error) {
	if ttl <= 0 {
		return nil, errors.New("transaction TTL must be positive")
	}
	return &Manager{transactions: map[string]*record{}, fileLocks: map[string]string{}, ttl: ttl, now: time.Now, oracle: oracle}, nil
}

func newToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func equalToken(want, got string) bool {
	if len(want) != 64 || len(got) != 64 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

func (m *Manager) auditLocked(id, event, digest string) {
	prev := ""
	if n := len(m.audit); n > 0 {
		prev = m.audit[n-1].SHA256
	}
	e := AuditEvent{Sequence: uint64(len(m.audit) + 1), TransactionID: id, Event: event, CandidateDigest: digest, PreviousSHA256: prev}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s\x00%s\x00%s", e.Sequence, e.TransactionID, e.Event, e.CandidateDigest, e.PreviousSHA256)))
	e.SHA256 = hex.EncodeToString(sum[:])
	m.audit = append(m.audit, e)
}
func (m *Manager) AuditSnapshot() []AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]AuditEvent(nil), m.audit...)
}
func (m *Manager) releaseLocked(id string, r *record) { delete(m.fileLocks, r.file) }
func (m *Manager) rejectLocked(id string, r *record, reason string) {
	r.state = Rejected
	r.commitToken = ""
	m.releaseLocked(id, r)
	m.auditLocked(id, "rejected:"+reason, r.transaction.CandidateDigest)
}
func (m *Manager) getLocked(id string) (*record, error) {
	r, ok := m.transactions[id]
	if !ok {
		return nil, ErrUnknown
	}
	if r.state != Rejected && r.state != Committed && !m.now().Before(r.expiresAt) {
		m.rejectLocked(id, r, "expired")
		return nil, ErrExpired
	}
	return r, nil
}
func (m *Manager) verifyRevision(r *record) ([]byte, error) {
	source, err := os.ReadFile(r.file)
	if err != nil {
		return nil, err
	}
	if engine.SHA(source) != r.sourceSHA256 {
		return nil, ErrStale
	}
	return source, nil
}

// Begin generates and seals candidate records before publishing only summaries
// and a randomly generated reconnaissance capability to an agent. A file-wide
// lock is deliberately conservative: this is not yet a symbol-scoped lock.
func (m *Manager) Begin(req agentproto.RecognitionRequest) (Menu, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if req.TransactionID == "" {
		return Menu{}, errors.New("empty transaction ID")
	}
	// A previous owner may have expired without making another API call.
	// Retire all expired live transactions before checking the file lock.
	for previousID, old := range m.transactions {
		if old.state != Rejected && old.state != Committed && !m.now().Before(old.expiresAt) {
			m.rejectLocked(previousID, old, "expired")
		}
	}
	if _, exists := m.transactions[req.TransactionID]; exists {
		return Menu{}, errors.New("transaction ID already exists")
	}
	path, err := filepath.Abs(req.Selector.File)
	if err != nil {
		return Menu{}, err
	}
	path = filepath.Clean(path)
	// Require the caller to supply a canonical absolute path; no base-name matching.
	if req.Selector.File != path {
		return Menu{}, errors.New("selector file must be an absolute clean path")
	}
	if _, locked := m.fileLocks[path]; locked {
		return Menu{}, ErrLocked
	}
	source, err := os.ReadFile(path)
	if err != nil {
		return Menu{}, err
	}
	if engine.SHA(source) != req.Selector.FileSHA256 {
		return Menu{}, ErrStale
	}
	catalog, err := recon.Discover(path, source, req)
	if err != nil {
		return Menu{}, err
	}
	reconToken, err := newToken()
	if err != nil {
		return Menu{}, err
	}
	tx, err := agentproto.NewTransaction(req.TransactionID, req.Selector, req.Intent)
	if err != nil {
		return Menu{}, err
	}
	expiry := m.now().Add(m.ttl)
	m.transactions[req.TransactionID] = &record{state: Reconnaissance, file: path, sourceSHA256: engine.SHA(source), catalog: catalog, transaction: tx, reconToken: reconToken, expiresAt: expiry}
	m.fileLocks[path] = req.TransactionID
	m.auditLocked(req.TransactionID, "reconnaissance", "")
	return Menu{TransactionID: req.TransactionID, ReconToken: reconToken, ExpiresAt: expiry, Catalog: catalog.Response()}, nil
}

// Choose selects only a trusted registry ID; no client patch is accepted.
func (m *Manager) Choose(id, reconToken, candidateID string) (Receipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.getLocked(id)
	if err != nil {
		return Receipt{}, err
	}
	if r.state != Reconnaissance {
		return Receipt{}, ErrState
	}
	if !equalToken(r.reconToken, reconToken) {
		return Receipt{}, ErrToken
	}
	if err = r.transaction.SelectCandidate(r.catalog, candidateID); err != nil {
		return Receipt{}, err
	}
	source, err := m.verifyRevision(r)
	if err != nil {
		m.rejectLocked(id, r, "stale")
		return Receipt{}, err
	}
	_, patch, err := r.catalog.Resolve(candidateID, id, r.sourceSHA256)
	if err != nil {
		return Receipt{}, err
	}
	candidate := engine.Apply(r.file, source, patch)
	if !candidate.OK || candidate.AfterSHA256 != r.transaction.CandidateOutputSHA256 {
		m.rejectLocked(id, r, "preflight")
		return Receipt{}, errors.New("candidate preflight or output identity failed")
	}
	r.candidateSource = []byte(candidate.UpdatedSource)
	r.state = Chosen
	m.auditLocked(id, "chosen", r.transaction.CandidateDigest)
	return Receipt{TransactionID: id, State: r.state, CandidateID: r.transaction.CandidateID, OutputSHA256: r.transaction.CandidateOutputSHA256}, nil
}

// Validate NEVER consumes an agent-supplied JSON validation report. Until a
// genuinely isolated, privileged validator is installed it always fails closed.
func (m *Manager) Validate(ctx context.Context, id, reconToken string) (Receipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.getLocked(id)
	if err != nil {
		return Receipt{}, err
	}
	if r.state != Chosen {
		return Receipt{}, ErrState
	}
	if !equalToken(r.reconToken, reconToken) {
		return Receipt{}, ErrToken
	}
	if m.oracle == nil {
		return Receipt{}, ErrValidatorUnavailable
	}
	if _, err = m.verifyRevision(r); err != nil {
		m.rejectLocked(id, r, "stale")
		return Receipt{}, err
	}
	work := validationWork{transactionID: id, sourceFile: r.file, sourceSHA256: r.sourceSHA256, candidateDigest: r.transaction.CandidateDigest, candidateOutputSHA256: r.transaction.CandidateOutputSHA256, candidateSource: append([]byte(nil), r.candidateSource...)}
	if err = m.oracle.Validate(ctx, work); err != nil {
		m.rejectLocked(id, r, "validation")
		return Receipt{}, err
	}
	if err = ctx.Err(); err != nil {
		m.rejectLocked(id, r, "canceled")
		return Receipt{}, err
	}
	if engine.SHA(work.candidateSource) != work.candidateOutputSHA256 {
		m.rejectLocked(id, r, "output_digest")
		return Receipt{}, errors.New("candidate output changed during validation")
	}
	if _, err = m.verifyRevision(r); err != nil {
		m.rejectLocked(id, r, "stale")
		return Receipt{}, err
	}
	token, err := newToken()
	if err != nil {
		return Receipt{}, err
	}
	r.commitToken = token
	r.state = Approved
	m.auditLocked(id, "approved", r.transaction.CandidateDigest)
	return Receipt{TransactionID: id, State: Approved, CandidateID: r.transaction.CandidateID, OutputSHA256: r.transaction.CandidateOutputSHA256, CommitToken: token}, nil
}

// Commit consumes the one-time capability, rechecks the source version and
// calls the existing single-file atomic writer. This is NOT a multi-file
// transaction, and the underlying writer has an external-writer TOCTOU window.
// No production commit is possible until a trusted validator is installed.
func (m *Manager) Commit(id, commitToken string) (Receipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.getLocked(id)
	if err != nil {
		return Receipt{}, err
	}
	if r.state != Approved {
		return Receipt{}, ErrState
	}
	if !equalToken(r.commitToken, commitToken) {
		return Receipt{}, ErrToken
	}
	source, err := m.verifyRevision(r)
	if err != nil {
		m.rejectLocked(id, r, "stale")
		return Receipt{}, err
	}
	if engine.SHA(r.candidateSource) != r.transaction.CandidateOutputSHA256 {
		m.rejectLocked(id, r, "digest")
		return Receipt{}, errors.New("candidate output identity mismatch")
	}
	// A failed write is terminal; no replay of the token.
	r.commitToken = ""
	if err := engine.WriteAtomic(r.file, source, string(r.candidateSource)); err != nil {
		m.rejectLocked(id, r, "write_failed")
		return Receipt{}, err
	}
	r.state = Committed
	m.releaseLocked(id, r)
	m.auditLocked(id, "committed", r.transaction.CandidateDigest)
	return Receipt{TransactionID: id, State: Committed, CandidateID: r.transaction.CandidateID, OutputSHA256: r.transaction.CandidateOutputSHA256}, nil
}

func (m *Manager) Reject(id, reconToken string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.getLocked(id)
	if err != nil {
		return err
	}
	if r.state == Rejected || r.state == Committed {
		return ErrState
	}
	if !equalToken(r.reconToken, reconToken) {
		return ErrToken
	}
	m.rejectLocked(id, r, "client_cancel")
	return nil
}
