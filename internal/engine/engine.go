// Package engine applies deliberately constrained edits to Go syntax trees.
// This prototype supports one operation: changing an existing binary operator
// in a uniquely identified assignment expression inside a named function.
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

// Patch is a non-textual operator mutation; no raw replacement source is accepted.
// The target is resolved by function and left-hand side of the assignment.
type Patch struct {
	Action string `json:"action"`
	Target struct {
		Function      string `json:"function"`
		AssignmentLHS string `json:"assignment_lhs"`
	} `json:"target"`
	ExpectedOperator string `json:"expected_operator"`
	NewOperator      string `json:"new_operator"`
	// Optional optimistic concurrency precondition, whole file SHA-256 hex.
	ExpectedFileSHA256 string `json:"expected_file_sha256,omitempty"`
}

type Diagnostic struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`
}

type Result struct {
	OK            bool         `json:"ok"`
	Written       bool         `json:"written"`
	Action        string       `json:"action"`
	BeforeSHA256  string       `json:"before_sha256,omitempty"`
	AfterSHA256   string       `json:"after_sha256,omitempty"`
	UpdatedSource string       `json:"updated_source,omitempty"`
	Diagnostics   []Diagnostic `json:"diagnostics"`
}

func SHA(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

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
	if p.Target.Function == "" || p.Target.AssignmentLHS == "" {
		return p, errors.New("target.function and target.assignment_lhs are required")
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

// Apply changes one operator in memory, formats and re-parses the candidate,
// then type-checks the whole directory package before returning a candidate.
// It does not write to the source tree.
func Apply(path string, source []byte, p Patch) Result {
	result := Result{Action: p.Action, BeforeSHA256: SHA(source), Diagnostics: []Diagnostic{}}
	reject := func(code, msg string, line int) Result {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: code, Message: msg, File: filepath.Base(path), Line: line})
		return result
	}
	if p.ExpectedFileSHA256 != "" && !strings.EqualFold(result.BeforeSHA256, p.ExpectedFileSHA256) {
		return reject("GOAI-CONFLICT-001", "file hash differs from expected_file_sha256", 0)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, source, parser.AllErrors|parser.ParseComments)
	if err != nil {
		return reject("GOAI-PARSE-001", err.Error(), 0)
	}
	var matches []*ast.BinaryExpr
	var wrongOperators []string
	// Function matching is syntactic and supports a receiver method or plain function.
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != p.Target.Function || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			assign, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, lhs := range assign.Lhs {
				if exprText(fset, lhs) != p.Target.AssignmentLHS {
					continue
				}
				if i >= len(assign.Rhs) {
					continue
				}
				binary, ok := assign.Rhs[i].(*ast.BinaryExpr)
				if !ok {
					continue
				}
				if binary.Op == operator(p.ExpectedOperator) {
					matches = append(matches, binary)
				} else {
					wrongOperators = append(wrongOperators, binary.Op.String())
				}
			}
			return true
		})
	}
	if len(matches) == 0 {
		if len(wrongOperators) != 0 {
			return reject("GOAI-CONFLICT-002", "expected operator not found; actual operator(s): "+strings.Join(wrongOperators, ", "), 0)
		}
		return reject("GOAI-TARGET-001", "no matching assignment with a binary expression", 0)
	}
	if len(matches) != 1 {
		return reject("GOAI-AMBIGUOUS-001", fmt.Sprintf("target matched %d binary expressions; no edit was made", len(matches)), 0)
	}
	line := fset.Position(matches[0].Pos()).Line
	matches[0].Op = operator(p.NewOperator)
	var out bytes.Buffer
	if err := format.Node(&out, fset, file); err != nil {
		return reject("GOAI-FORMAT-001", err.Error(), line)
	}
	candidate := out.Bytes()
	if _, err := parser.ParseFile(token.NewFileSet(), path, candidate, parser.AllErrors); err != nil {
		return reject("GOAI-PARSE-002", err.Error(), line)
	}
	diagnostics := typecheckPackage(path, candidate)
	if len(diagnostics) > 0 {
		result.Diagnostics = diagnostics
		return result
	}
	result.OK = true
	result.AfterSHA256 = SHA(candidate)
	result.UpdatedSource = string(candidate)
	return result
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
				issues = append(issues, Diagnostic{Code: "GOAI-POLICY-001", Message: "unsafe and reflect imports are disallowed by prototype policy", File: filepath.Base(pos.Filename), Line: pos.Line})
			}
			return true
		})
	}
	if len(issues) > 0 {
		return issues
	}
	conf := types.Config{Importer: importer.Default(), Error: func(e error) {
		issue := Diagnostic{Code: "GOAI-TYPE-001", Message: e.Error()}
		if te, ok := e.(types.Error); ok {
			pos := fset.Position(te.Pos)
			issue.File, issue.Line = filepath.Base(pos.Filename), pos.Line
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
