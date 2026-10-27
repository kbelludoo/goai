// Package engine applies deliberately constrained edits to Go syntax trees.
//
// The prototype supports one operation: changing an existing binary operator in
// a uniquely identified assignment expression inside a named function, method,
// or symbol. Everything the engine emits is meant to be consumed by a program
// (an agent or a CI job), not read by a human: versioned envelopes, stable
// symbol identifiers, and refusals that say how to retry.
package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Protocol identifies the JSON contract emitted by this package. Agents should
// pin it: fields may be added within a minor version, but not repurposed.
const Protocol = "goai/0.2"

// Target selects one editable site. Three selectors are accepted and may be
// combined; combining them only narrows the match:
//
//   - Function: bare function or method name, syntactic.
//   - Receiver: receiver type as written (`*Wallet`, `Wallet`, `*List[T]`).
//   - Symbol: stable identifier from `goai context`, e.g. `calc.(*Wallet).Add`.
//
// When several sites still match, the engine refuses and returns them as
// candidates; Occurrence (1-based, source order) then disambiguates in a retry.
type Target struct {
	Function      string `json:"function,omitempty"`
	Symbol        string `json:"symbol,omitempty"`
	Receiver      string `json:"receiver,omitempty"`
	AssignmentLHS string `json:"assignment_lhs"`
	Occurrence    *int   `json:"occurrence,omitempty"`
}

// Patch is a non-textual operator mutation; no raw replacement source is accepted.
type Patch struct {
	Action string `json:"action"`
	Target Target `json:"target"`
	// ExpectedOperator is a mandatory precondition, not a hint.
	ExpectedOperator string `json:"expected_operator"`
	NewOperator      string `json:"new_operator"`
	// Optional optimistic concurrency precondition, whole file SHA-256 hex.
	ExpectedFileSHA256 string `json:"expected_file_sha256,omitempty"`
}

// Result is the patch envelope.
type Result struct {
	Protocol      string       `json:"protocol"`
	OK            bool         `json:"ok"`
	Written       bool         `json:"written"`
	Action        string       `json:"action"`
	File          string       `json:"file,omitempty"`
	BeforeSHA256  string       `json:"before_sha256,omitempty"`
	AfterSHA256   string       `json:"after_sha256,omitempty"`
	UpdatedSource string       `json:"updated_source,omitempty"`
	Diagnostics   []Diagnostic `json:"diagnostics"`
	NextActions   []NextAction `json:"next_actions,omitempty"`
}

func SHA(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ParsePatch validates structure only. Semantic preconditions (hash, operator,
// target uniqueness) are checked against the file in Apply.
func ParsePatch(raw []byte) (Patch, error) {
	var p Patch
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, fmt.Errorf("invalid patch: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) { // strict single JSON object
		return p, fmt.Errorf("invalid patch: extra JSON tokens")
	}
	if p.Action != "replace_binary_operator" {
		return p, errors.New("action must be replace_binary_operator")
	}
	if p.Target.Function == "" && p.Target.Symbol == "" {
		return p, errors.New("target.function or target.symbol is required")
	}
	if p.Target.AssignmentLHS == "" {
		return p, errors.New("target.assignment_lhs is required")
	}
	if p.Target.Function != "" && p.Target.Symbol != "" {
		return p, errors.New("use target.function or target.symbol, not both")
	}
	if p.Target.Occurrence != nil && *p.Target.Occurrence < 1 {
		return p, errors.New("target.occurrence is 1-based and must be >= 1")
	}
	if !allowedOperator(p.ExpectedOperator) || !allowedOperator(p.NewOperator) {
		return p, errors.New("supported binary operators: +, -, *, /")
	}
	if p.ExpectedOperator == p.NewOperator {
		return p, errors.New("operator must change")
	}
	if p.ExpectedFileSHA256 != "" {
		if len(p.ExpectedFileSHA256) != 64 {
			return p, errors.New("expected_file_sha256 must have 64 hex digits")
		}
		if _, err := hex.DecodeString(p.ExpectedFileSHA256); err != nil {
			return p, errors.New("expected_file_sha256 must be hexadecimal")
		}
	}
	return p, nil
}

func allowedOperator(s string) bool {
	switch s {
	case "+", "-", "*", "/":
		return true
	}
	return false
}

func operator(s string) token.Token {
	switch s {
	case "+":
		return token.ADD
	case "-":
		return token.SUB
	case "*":
		return token.MUL
	case "/":
		return token.QUO
	}
	panic("unsupported token")
}

func exprText(fset *token.FileSet, n ast.Node) string {
	var b bytes.Buffer
	if err := format.Node(&b, fset, n); err != nil {
		return ""
	}
	return b.String()
}

// compactText renders a syntax node on a single line. Signatures are references
// for an agent to read, not code to paste, so line wrapping only costs tokens.
func compactText(fset *token.FileSet, n ast.Node) string {
	return strings.Join(strings.Fields(exprText(fset, n)), " ")
}

// targetHit is one editable site: an assignment whose right side is a binary
// expression, resolved to the enclosing function's stable symbol.
type targetHit struct {
	bin *ast.BinaryExpr
	fn  string
	lhs string
	pos token.Position
}

// scanTargets walks the file in source order and returns every assignment with a
// binary right-hand side inside a function accepted by keep. Source order is the
// contract behind Target.Occurrence.
func scanTargets(pkg string, fset *token.FileSet, file *ast.File, keep func(*ast.FuncDecl) bool) []targetHit {
	var hits []targetHit
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !keep(fn) {
			continue
		}
		id := funcSymbolID(pkg, fset, fn)
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			assign, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, lhs := range assign.Lhs {
				if i >= len(assign.Rhs) {
					continue
				}
				binary, ok := assign.Rhs[i].(*ast.BinaryExpr)
				if !ok {
					continue
				}
				hits = append(hits, targetHit{
					bin: binary,
					fn:  id,
					lhs: exprText(fset, lhs),
					pos: fset.Position(binary.Pos()),
				})
			}
			return true
		})
	}
	return hits
}

// sitesOf turns hits into machine-actionable candidates. Occurrence is always
// relative to the full filtered hit list, so a returned RetryTarget can be sent
// back verbatim as the next patch target.
func sitesOf(hits []targetHit, base string) []Site {
	out := make([]Site, 0, len(hits))
	for i, h := range hits {
		occurrence := i + 1
		out = append(out, Site{
			Symbol:        h.fn,
			AssignmentLHS: h.lhs,
			Operator:      h.bin.Op.String(),
			File:          base,
			Line:          h.pos.Line,
			Column:        h.pos.Column,
			Occurrence:    occurrence,
			RetryTarget: Target{
				Symbol:        h.fn,
				AssignmentLHS: h.lhs,
				Occurrence:    &occurrence,
			},
		})
	}
	return out
}

// Apply changes one operator in memory, formats and re-parses the candidate,
// then type-checks the whole directory package before returning a candidate.
// It does not write to the source tree. Refusals carry a hint, a retryable flag,
// and (for ambiguity and precondition failures) the candidate set.
func Apply(path string, source []byte, p Patch) Result {
	base := filepath.Base(path)
	result := Result{
		Protocol:     Protocol,
		Action:       p.Action,
		File:         base,
		BeforeSHA256: SHA(source),
		Diagnostics:  []Diagnostic{},
	}
	fail := func(d Diagnostic) Result {
		result.Diagnostics = append(result.Diagnostics, d)
		return result
	}
	if p.ExpectedFileSHA256 != "" && !strings.EqualFold(result.BeforeSHA256, p.ExpectedFileSHA256) {
		return fail(Diagnostic{
			Code:      "GOAI-CONFLICT-001",
			Message:   "file hash differs from expected_file_sha256",
			Hint:      "re-read the file and retry with the sha256 reported by `goai context`",
			Retryable: true,
			File:      base,
		})
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, source, parser.AllErrors|parser.ParseComments)
	if err != nil {
		return fail(Diagnostic{Code: "GOAI-PARSE-001", Message: err.Error(), File: base})
	}
	pkg := file.Name.Name
	symbol := ""
	if p.Target.Symbol != "" {
		symbol = normalizeSymbol(pkg, p.Target.Symbol)
	}
	receiver := strings.TrimSpace(p.Target.Receiver)

	hits := scanTargets(pkg, fset, file, func(fn *ast.FuncDecl) bool {
		if symbol != "" && funcSymbolID(pkg, fset, fn) != symbol {
			return false
		}
		if p.Target.Function != "" && fn.Name.Name != p.Target.Function {
			return false
		}
		if receiver != "" && receiverText(fset, fn.Recv) != receiver {
			return false
		}
		return true
	})
	if p.Target.AssignmentLHS != "" {
		matched := make([]targetHit, 0, len(hits))
		for _, h := range hits {
			if h.lhs == p.Target.AssignmentLHS {
				matched = append(matched, h)
			}
		}
		hits = matched
	}
	candidates := sitesOf(hits, base)

	if len(hits) == 0 {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{
			Code:      "GOAI-TARGET-001",
			Message:   "no assignment with a binary right-hand side matched the target",
			Hint:      "run `goai context -file <file>` and copy a symbol/assignment pair from its targets list",
			Retryable: true,
			File:      base,
		})
		result.NextActions = append(result.NextActions, NextAction{
			Kind:        "reconnoiter",
			Description: "list symbol identifiers and editable assignment sites for the file, then retry the patch",
		})
		return result
	}

	expected := operator(p.ExpectedOperator)
	var selected targetHit
	if p.Target.Occurrence != nil {
		i := *p.Target.Occurrence
		if i > len(hits) {
			return fail(Diagnostic{
				Code:       "GOAI-TARGET-002",
				Message:    fmt.Sprintf("target.occurrence %d is out of range: the target matched %d assignments", i, len(hits)),
				Hint:       "pick an occurrence from candidates (1-based, source order)",
				Retryable:  true,
				File:       base,
				Candidates: candidates,
			})
		}
		selected = hits[i-1]
		if selected.bin.Op != expected {
			return fail(operatorConflict(base, p.ExpectedOperator, selected, candidates))
		}
	} else {
		matched := make([]targetHit, 0, len(hits))
		var others []targetHit
		for _, h := range hits {
			if h.bin.Op == expected {
				matched = append(matched, h)
			} else {
				others = append(others, h)
			}
		}
		switch {
		case len(matched) == 1:
			selected = matched[0]
		case len(matched) > 1:
			result.Diagnostics = append(result.Diagnostics, Diagnostic{
				Code:       "GOAI-AMBIGUOUS-001",
				Message:    fmt.Sprintf("target matched %d binary expressions; no edit was made", len(matched)),
				Hint:       "retry with target.occurrence (or send a candidate's retry_target) for the site whose operator equals expected_operator",
				Retryable:  true,
				File:       base,
				Candidates: candidates,
			})
			result.NextActions = append(result.NextActions, NextAction{
				Kind:        "retry_with_occurrence",
				Description: "resend the patch with occurrence set to the chosen candidate",
			})
			return result
		case len(others) > 0:
			return fail(operatorConflict(base, p.ExpectedOperator, others[0], candidates))
		default:
			return fail(Diagnostic{
				Code:      "GOAI-TARGET-001",
				Message:   "target matched assignments but none had a binary right-hand side",
				Hint:      "re-read the file; the target text may have changed",
				Retryable: true,
				File:      base,
			})
		}
	}

	line := selected.pos.Line
	selected.bin.Op = operator(p.NewOperator)
	var out bytes.Buffer
	if err := format.Node(&out, fset, file); err != nil {
		return fail(Diagnostic{Code: "GOAI-FORMAT-001", Message: err.Error(), File: base, Line: line})
	}
	candidate := out.Bytes()
	if _, err := parser.ParseFile(token.NewFileSet(), path, candidate, parser.AllErrors); err != nil {
		return fail(Diagnostic{Code: "GOAI-PARSE-002", Message: err.Error(), File: base, Line: line})
	}
	diagnostics := typecheckPackage(path, candidate)
	if len(diagnostics) > 0 {
		result.Diagnostics = diagnostics
		return result
	}
	result.OK = true
	result.AfterSHA256 = SHA(candidate)
	result.UpdatedSource = string(candidate)
	result.NextActions = append(result.NextActions,
		NextAction{
			Kind:        "apply_write",
			Description: "the change is validated in memory only; resend with -write to replace the file atomically",
		},
		NextAction{
			Kind:        "verify_with_tests",
			Description: "type-checking does not prove behaviour; run `go test ./...` in the package directory before trusting the edit",
		},
	)
	return result
}

func operatorConflict(base, expected string, h targetHit, candidates []Site) Diagnostic {
	return Diagnostic{
		Code:       "GOAI-CONFLICT-002",
		Message:    fmt.Sprintf("expected operator %q but found %q at line %d", expected, h.bin.Op.String(), h.pos.Line),
		Hint:       "re-read the target; either update expected_operator or choose another candidate",
		Retryable:  true,
		File:       base,
		Line:       h.pos.Line,
		Column:     h.pos.Column,
		Candidates: candidates,
	}
}

// Check reports parse and type-check diagnostics without touching the tree.
// It is the cheap "did I break it?" probe for an agent loop.
func Check(path string, source []byte) Result {
	base := filepath.Base(path)
	result := Result{Protocol: Protocol, Action: "check", File: base, BeforeSHA256: SHA(source), Diagnostics: []Diagnostic{}}
	if _, err := parser.ParseFile(token.NewFileSet(), path, source, parser.AllErrors|parser.ParseComments); err != nil {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: "GOAI-PARSE-001", Message: err.Error(), File: base})
		return result
	}
	diagnostics := typecheckPackage(path, source)
	result.Diagnostics = append(result.Diagnostics, diagnostics...)
	result.OK = len(diagnostics) == 0
	if result.OK {
		result.NextActions = append(result.NextActions, NextAction{
			Kind:        "verify_with_tests",
			Description: "type-checking passed; behaviour still needs `go test ./...`",
		})
	}
	return result
}

// WithoutKind returns actions without the given kind, preserving order.
func WithoutKind(actions []NextAction, kind string) []NextAction {
	out := make([]NextAction, 0, len(actions))
	for _, a := range actions {
		if a.Kind != kind {
			out = append(out, a)
		}
	}
	return out
}

// typecheckPackage is for ordinary single-directory Go packages with standard-library
// imports. It does not implement module-aware external package resolution, build tags,
// or multi-package workspaces; those belong in a production build backend.
func typecheckPackage(target string, candidate []byte) []Diagnostic {
	dir := filepath.Dir(target)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []Diagnostic{{Code: "GOAI-IO-001", Message: err.Error()}}
	}
	fset := token.NewFileSet()
	files := []*ast.File{}
	names := []string{}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") && !strings.HasSuffix(entry.Name(), "_test.go") {
			names = append(names, filepath.Join(dir, entry.Name()))
		}
	}
	sort.Strings(names)
	targetAbs, _ := filepath.Abs(target)
	for _, name := range names {
		nameAbs, _ := filepath.Abs(name)
		var b []byte
		if nameAbs == targetAbs {
			b = candidate
		} else {
			b, err = os.ReadFile(name)
			if err != nil {
				return []Diagnostic{{Code: "GOAI-IO-002", File: filepath.Base(name), Message: err.Error()}}
			}
		}
		f, e := parser.ParseFile(fset, name, b, parser.AllErrors|parser.ParseComments)
		if e != nil {
			return []Diagnostic{{Code: "GOAI-PARSE-003", File: filepath.Base(name), Message: e.Error()}}
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		return []Diagnostic{{Code: "GOAI-PACKAGE-001", Message: "no Go files found"}}
	}
	pkgName := files[0].Name.Name
	for _, f := range files {
		if f.Name.Name != pkgName {
			return []Diagnostic{{Code: "GOAI-PACKAGE-002", Message: "mismatched package names"}}
		}
	}
	issues := []Diagnostic{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			imp, ok := n.(*ast.ImportSpec)
			if ok && (imp.Path.Value == `"unsafe"` || imp.Path.Value == `"reflect"`) {
				pos := fset.Position(imp.Pos())
				issues = append(issues, Diagnostic{
					Code:      "GOAI-POLICY-001",
					Message:   "unsafe and reflect imports are disallowed by prototype policy",
					Hint:      "this deny-list is a demonstration policy, not a language rule; change the policy or remove the import",
					Retryable: false,
					File:      filepath.Base(pos.Filename),
					Line:      pos.Line,
					Column:    pos.Column,
				})
			}
			return true
		})
	}
	if len(issues) > 0 {
		return issues
	}
	conf := types.Config{Importer: importer.Default(), Error: func(e error) {
		issue := Diagnostic{
			Code:      "GOAI-TYPE-001",
			Message:   e.Error(),
			Hint:      "the candidate does not type-check; the requested operator or target is probably invalid for these operand types",
			Retryable: true,
		}
		if te, ok := e.(types.Error); ok {
			pos := fset.Position(te.Pos)
			issue.File, issue.Line, issue.Column = filepath.Base(pos.Filename), pos.Line, pos.Column
		}
		issues = append(issues, issue)
	}}
	_, _ = conf.Check(pkgName, fset, files, nil)
	return issues
}

// WriteAtomic replaces a source file after validation; existing file permissions
// are preserved. A file hash is rechecked just before replace to avoid stale writes.
func WriteAtomic(path string, before []byte, updated string) error {
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if SHA(current) != SHA(before) {
		return errors.New("GOAI-CONFLICT-003: file changed before write")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".goai-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(updated); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
