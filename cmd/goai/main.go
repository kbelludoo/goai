package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/kbelludoo/goai/internal/engine"
)

func main() {
	file := flag.String("file", "", "Go file to inspect and optionally update")
	patchFile := flag.String("patch", "", "JSON patch instruction")
	write := flag.Bool("write", false, "write the validated candidate to source")
	flag.Parse()
	out := engine.Result{Diagnostics: []engine.Diagnostic{}}
	errorResult := func(code, message string) {
		out.Diagnostics = append(out.Diagnostics, engine.Diagnostic{Code: code, Message: message})
		printJSON(out)
		os.Exit(1)
	}
	if *file == "" || *patchFile == "" {
		errorResult("GOAI-USAGE-001", "usage: goai -file file.go -patch patch.json [-write]")
	}
	patchBytes, err := os.ReadFile(*patchFile)
	if err != nil {
		errorResult("GOAI-IO-003", err.Error())
	}
	patch, err := engine.ParsePatch(patchBytes)
	if err != nil {
		errorResult("GOAI-PATCH-001", err.Error())
	}
	original, err := os.ReadFile(*file)
	if err != nil {
		errorResult("GOAI-IO-004", err.Error())
	}
	out = engine.Apply(*file, original, patch)
	if !out.OK {
		printJSON(out)
		os.Exit(2)
	}
	if *write {
		if err := engine.WriteAtomic(*file, original, out.UpdatedSource); err != nil {
			out.OK = false
			out.Diagnostics = append(out.Diagnostics, engine.Diagnostic{Code: "GOAI-WRITE-001", Message: err.Error()})
			printJSON(out)
			os.Exit(3)
		}
		out.Written = true
		out.UpdatedSource = ""
	}
	printJSON(out)
}

func printJSON(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(b))
}
