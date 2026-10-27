// Package recon discovers conservative, bounded AST mutations without
// executing user code or editing the original source.
package recon

import (
	"bytes"
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

// Discover returns a private, revision-bound candidate catalog. Only its
// Response() should be serialized to an agent. The agent replies with an ID.
// No sandbox/executor is implied by engine.Apply's syntax/type preflight.
func Discover(sourcePath string, source []byte, req agentproto.RecognitionRequest) (*agentproto.CandidateCatalog, error) {
	actual := engine.SHA(source)
	if req.TransactionID == "" {
		return nil, errors.New("missing tx_id")
	}
	if req.Selector.File == "" || filepath.Clean(req.Selector.File) != filepath.Clean(sourcePath) {
		return nil, errors.New("selector must match exact normalized source path")
	}
	if req.Selector.MatchPolicy != "exactly_one" || req.Selector.Declaration == "" || !agentproto.IsSHA256(req.Selector.FileSHA256) {
		return nil, errors.New("invalid selector (declaration, hash and exactly_one required)")
	}
	if actual != strings.ToLower(req.Selector.FileSHA256) {
		return nil, errors.New("GOAI-CONFLICT: stale source revision")
	}
	if req.Intent.Kind != agentproto.FixArithmeticLogic {
		return nil, errors.New("unsupported intent")
	}
	if req.MaxCandidates < 0 || req.MaxCandidates > candidateCap {
		return nil, fmt.Errorf("max_candidates must be between 0 and %d", candidateCap)
	}
	limit := req.MaxCandidates
	if limit == 0 {
		limit = candidateCap
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, sourcePath, source, parser.AllErrors)
	if err != nil {
		return nil, err
	}
	if req.Selector.Package != "" && req.Selector.Package != f.Name.Name {
		return nil, errors.New("selector package does not match parsed package")
	}
	if strings.Contains(req.Selector.Declaration, ".") {
		return nil, errors.New("receiver-qualified selectors not yet supported")
	}
	catalog, err := agentproto.NewCandidateCatalog(req.TransactionID, actual)
	if err != nil {
		return nil, err
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != req.Selector.Declaration || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
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
				patch := engine.Patch{Action: "replace_binary_operator", ExpectedOperator: from, NewOperator: to, ExpectedFileSHA256: actual}
				patch.Target.Function, patch.Target.AssignmentLHS = fn.Name.Name, lhsText
				result := engine.Apply(sourcePath, source, patch)
				if !result.OK {
					catalog.AddDiagnostics(result.Diagnostics...)
					continue
				}
				if catalog.Len() >= limit {
					catalog.SetCapped()
					continue
				}
				_, err := catalog.Register(patch, result.AfterSHA256, fmt.Sprintf("Change %s to %s in assignment to %s", from, to, lhsText))
				if err != nil {
					catalog.AddDiagnostics(engine.Diagnostic{Code: "GOAI-CATALOG-001", Message: err.Error()})
				}
			}
			return true
		})
	}
	if err := catalog.Seal(); err != nil {
		return nil, err
	}
	return catalog, nil
}
