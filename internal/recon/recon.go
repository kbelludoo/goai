// Package recon discovers conservative, bounded AST mutation candidates.
// It never guesses the business-correct answer, executes tests or writes files.
package recon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"

	"github.com/kbelludoo/goai/internal/agentproto"
	"github.com/kbelludoo/goai/internal/engine"
)

const candidateCap = 16

func printed(fset *token.FileSet, n ast.Node) string {
	var out bytes.Buffer
	if err := format.Node(&out, fset, n); err != nil {
		return ""
	}
	return out.String()
}

func candidateID(revision, txID, lhs, oldOp, newOp string) string {
	sum := sha256.Sum256([]byte(revision + "\x00" + txID + "\x00" + lhs + "\x00" + oldOp + "\x00" + newOp))
	return hex.EncodeToString(sum[:])[:20]
}

// Discover returns only candidates that the existing 0.1 engine can target
// unambiguously and type-check. It deliberately supports only + <-> - now.
func Discover(sourcePath string, source []byte, req agentproto.RecognitionRequest) (agentproto.RecognitionResponse, error) {
	actual := engine.SHA(source)
	out := agentproto.RecognitionResponse{TransactionID: req.TransactionID, SourceSHA256: actual, Candidates: []agentproto.Candidate{}}
	if req.TransactionID == "" {
		return out, errors.New("missing tx_id")
	}
	if filepath.Base(req.Selector.File) != filepath.Base(sourcePath) || req.Selector.File == "" {
		return out, errors.New("selector file does not match requested source path")
	}
	if req.Selector.MatchPolicy != "exactly_one" || req.Selector.Declaration == "" || !agentproto.IsSHA256(req.Selector.FileSHA256) {
		return out, errors.New("invalid selector (declaration, hash and exactly_one required)")
	}
	if actual != strings.ToLower(req.Selector.FileSHA256) {
		return out, errors.New("GOAI-CONFLICT: stale source revision")
	}
	if req.Intent.Kind != agentproto.FixArithmeticLogic {
		return out, errors.New("unsupported intent")
	}
	if req.MaxCandidates < 0 || req.MaxCandidates > candidateCap {
		return out, fmt.Errorf("max_candidates must be between 0 and %d", candidateCap)
	}
	limit := req.MaxCandidates
	if limit == 0 {
		limit = candidateCap
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, sourcePath, source, parser.AllErrors)
	if err != nil {
		return out, err
	}
	if req.Selector.Package != "" && req.Selector.Package != f.Name.Name {
		return out, errors.New("selector package does not match parsed package")
	}
	// The existing engine accepts only a function name, not a receiver-qualified
	// symbol. Reject receiver-qualified selectors instead of pretending support.
	if strings.Contains(req.Selector.Declaration, ".") {
		return out, errors.New("receiver-qualified selectors not yet supported")
	}
	seen := map[string]bool{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != req.Selector.Declaration || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if len(out.Candidates) >= limit {
				return false
			}
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, lhs := range assign.Lhs {
				if i >= len(assign.Rhs) {
					continue
				}
				lhsText := printed(fset, lhs)
				if req.Selector.AssignmentLHS != "" && lhsText != req.Selector.AssignmentLHS {
					continue
				}
				binary, ok := assign.Rhs[i].(*ast.BinaryExpr)
				if !ok {
					continue
				}
				from, to := binary.Op.String(), ""
				switch from {
				case "+":
					to = "-"
				case "-":
					to = "+"
				default:
					continue
				}
				p := engine.Patch{Action: "replace_binary_operator", ExpectedOperator: from, NewOperator: to, ExpectedFileSHA256: actual}
				p.Target.Function, p.Target.AssignmentLHS = fn.Name.Name, lhsText
				id := candidateID(actual, req.TransactionID, lhsText, from, to)
				if seen[id] {
					continue
				}
				seen[id] = true
				// Full engine preflight: ambiguous or untypecheckable edits are
				// not offered as actionable candidates.
				result := engine.Apply(sourcePath, source, p)
				if !result.OK {
					out.Diagnostics = append(out.Diagnostics, result.Diagnostics...)
					continue
				}
				out.Candidates = append(out.Candidates, agentproto.Candidate{
					ID: id, TransactionID: req.TransactionID, SourceSHA256: actual,
					Description: fmt.Sprintf("Change %s to %s in assignment to %s", from, to, lhsText), Patch: p,
				})
				if len(out.Candidates) >= limit {
					return false
				}
			}
			return true
		})
	}
	return out, nil
}
