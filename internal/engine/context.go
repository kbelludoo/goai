package engine

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
)

// Context is a compact, token-bounded view of one file: identifiers an agent can
// cite, and the exact editable sites it can patch. It is deliberately not the
// file itself and not a type-checked API.
type Context struct {
	Protocol    string       `json:"protocol"`
	OK          bool         `json:"ok"`
	File        string       `json:"file"`
	SHA256      string       `json:"sha256"`
	Package     string       `json:"package"`
	Doc         string       `json:"doc,omitempty"`
	Imports     []Import     `json:"imports,omitempty"`
	Symbols     []Symbol     `json:"symbols"`
	Targets     []Site       `json:"targets,omitempty"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}

type Import struct {
	Path  string `json:"path"`
	Alias string `json:"alias,omitempty"`
	Line  int    `json:"line"`
}

// Symbol is one declaration an agent may need to name. Kind is one of
// func, method, type, field, interface_method, var, const.
type Symbol struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Signature string `json:"signature,omitempty"`
	Doc       string `json:"doc,omitempty"`
	Line      int    `json:"line"`
	Column    int    `json:"column"`
	Exported  bool   `json:"exported"`
}

// OutlineOptions controls how much context is returned. Brief drops doc comments
// and signatures; Typecheck adds compiler diagnostics at the cost of speed.
type OutlineOptions struct {
	Brief     bool
	Typecheck bool
}

// Outline parses one file and returns its identifiers and editable sites.
// A parse failure is reported as a diagnostic, not as a panic or plain text.
func Outline(path string, source []byte, opts OutlineOptions) Context {
	base := filepath.Base(path)
	out := Context{
		Protocol:    Protocol,
		File:        base,
		SHA256:      SHA(source),
		Symbols:     []Symbol{},
		Diagnostics: []Diagnostic{},
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, source, parser.AllErrors|parser.ParseComments)
	if err != nil {
		out.Diagnostics = append(out.Diagnostics, Diagnostic{Code: "GOAI-PARSE-001", Message: err.Error(), File: base})
		return out
	}
	out.OK = true
	out.Package = file.Name.Name
	if !opts.Brief {
		out.Doc = docText(file.Doc)
	}
	pkg := out.Package

	for _, imp := range file.Imports {
		entry := Import{Path: strings.Trim(imp.Path.Value, `"`), Line: fset.Position(imp.Pos()).Line}
		if imp.Name != nil {
			entry.Alias = imp.Name.Name
		}
		out.Imports = append(out.Imports, entry)
	}

	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			kind := "func"
			if d.Recv != nil {
				kind = "method"
			}
			pos := fset.Position(d.Pos())
			symbol := Symbol{
				ID:       funcSymbolID(pkg, fset, d),
				Kind:     kind,
				Line:     pos.Line,
				Column:   pos.Column,
				Exported: d.Name.IsExported(),
			}
			if !opts.Brief {
				symbol.Doc = docText(d.Doc)
				symbol.Signature = funcSignature(fset, d)
			}
			out.Symbols = append(out.Symbols, symbol)
		case *ast.GenDecl:
			out.Symbols = append(out.Symbols, declaredSymbols(pkg, fset, d, opts)...)
		}
	}

	hits := scanTargets(pkg, fset, file, func(*ast.FuncDecl) bool { return true })
	out.Targets = sitesOf(hits, base)

	if opts.Typecheck {
		out.Diagnostics = append(out.Diagnostics, typecheckPackage(path, source)...)
		out.OK = len(out.Diagnostics) == 0
	}
	return out
}

func declaredSymbols(pkg string, fset *token.FileSet, decl *ast.GenDecl, opts OutlineOptions) []Symbol {
	symbols := []Symbol{}
	for _, spec := range decl.Specs {
		switch sp := spec.(type) {
		case *ast.TypeSpec:
			pos := fset.Position(sp.Pos())
			symbol := Symbol{
				ID:       pkg + "." + sp.Name.Name,
				Kind:     "type",
				Line:     pos.Line,
				Column:   pos.Column,
				Exported: sp.Name.IsExported(),
			}
			if !opts.Brief {
				symbol.Doc = docText(decl.Doc)
				symbol.Signature = compactText(fset, sp.Type)
			}
			symbols = append(symbols, symbol)
			symbols = append(symbols, typeMembers(pkg, fset, sp, opts)...)
		case *ast.ValueSpec:
			kind := "var"
			if decl.Tok == token.CONST {
				kind = "const"
			}
			for _, name := range sp.Names {
				pos := fset.Position(name.Pos())
				symbol := Symbol{
					ID:       pkg + "." + name.Name,
					Kind:     kind,
					Line:     pos.Line,
					Column:   pos.Column,
					Exported: name.IsExported(),
				}
				if !opts.Brief {
					symbol.Doc = docText(decl.Doc)
					if sp.Type != nil {
						symbol.Signature = compactText(fset, sp.Type)
					}
				}
				symbols = append(symbols, symbol)
			}
		}
	}
	return symbols
}

// typeMembers lists struct fields and interface methods so an agent can address
// them without reading the type's body.
func typeMembers(pkg string, fset *token.FileSet, sp *ast.TypeSpec, opts OutlineOptions) []Symbol {
	if opts.Brief {
		return nil
	}
	members := []Symbol{}
	switch t := sp.Type.(type) {
	case *ast.StructType:
		for _, field := range t.Fields.List {
			name := ""
			exported := false
			var pos token.Position
			if len(field.Names) == 0 {
				name = strings.TrimPrefix(compactText(fset, field.Type), "*")
				exported = ast.IsExported(name)
				pos = fset.Position(field.Pos())
			} else {
				name = field.Names[0].Name
				exported = field.Names[0].IsExported()
				pos = fset.Position(field.Names[0].Pos())
			}
			members = append(members, Symbol{
				ID:        pkg + "." + sp.Name.Name + "." + name,
				Kind:      "field",
				Signature: compactText(fset, field.Type),
				Line:      pos.Line,
				Column:    pos.Column,
				Exported:  exported,
			})
		}
	case *ast.InterfaceType:
		for _, field := range t.Fields.List {
			if len(field.Names) == 0 {
				continue // embedded interface
			}
			pos := fset.Position(field.Names[0].Pos())
			members = append(members, Symbol{
				ID:        pkg + "." + sp.Name.Name + "." + field.Names[0].Name,
				Kind:      "interface_method",
				Signature: field.Names[0].Name + compactText(fset, field.Type),
				Line:      pos.Line,
				Column:    pos.Column,
				Exported:  field.Names[0].IsExported(),
			})
		}
	}
	return members
}
