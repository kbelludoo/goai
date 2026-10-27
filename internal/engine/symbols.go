package engine

import (
	"go/ast"
	"go/token"
	"strings"
)

// receiverText renders the receiver type exactly as written, without the
// variable name: `*Wallet`, `Wallet`, `*List[T]`.
func receiverText(fset *token.FileSet, recv *ast.FieldList) string {
	if recv == nil || len(recv.List) == 0 {
		return ""
	}
	return compactText(fset, recv.List[0].Type)
}

// funcSymbolID is the stable identifier for a function or method:
//
//	calc.Total               package-level function
//	calc.(*Wallet).Withdraw  pointer-receiver method
//	calc.(List[T]).Push      generic receiver, as written in the source
//
// Context and Apply both call this function, so an identifier printed by
// `goai context` is guaranteed to be accepted by `goai patch`.
func funcSymbolID(pkg string, fset *token.FileSet, fn *ast.FuncDecl) string {
	if recv := receiverText(fset, fn.Recv); recv != "" {
		return pkg + ".(" + recv + ")." + fn.Name.Name
	}
	return pkg + "." + fn.Name.Name
}

// normalizeSymbol accepts an identifier with or without the package prefix:
// `(*Wallet).Withdraw` and `calc.(*Wallet).Withdraw` are the same symbol.
func normalizeSymbol(pkg, symbol string) string {
	symbol = strings.TrimSpace(symbol)
	if symbol == "" {
		return ""
	}
	if strings.HasPrefix(symbol, pkg+".") {
		return symbol
	}
	return pkg + "." + symbol
}

// funcSignature prints a bodyless signature on one line.
func funcSignature(fset *token.FileSet, fn *ast.FuncDecl) string {
	signature := *fn
	signature.Doc = nil
	signature.Body = nil
	return compactText(fset, &signature)
}

const maxDocRunes = 320

// docText keeps doc comments short: they help an agent decide relevance, but
// they are not the reason to spend context.
func docText(cg *ast.CommentGroup) string {
	if cg == nil {
		return ""
	}
	text := strings.TrimSpace(cg.Text())
	if text == "" {
		return ""
	}
	runes := []rune(text)
	if len(runes) > maxDocRunes {
		return string(runes[:maxDocRunes]) + "..."
	}
	return text
}
