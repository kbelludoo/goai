// Command goai exposes the engine to a caller that is not a human: every mode
// prints one JSON envelope on stdout, and the exit code is the primary signal.
//
//	goai patch   -file f.go -patch p.json [-write]
//	goai context -file f.go [-brief] [-typecheck]
//	goai check   -file f.go
//
// The first positional argument selects the mode; omitting it keeps the original
// `goai -file f.go -patch p.json` invocation working.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/kbelludoo/goai/internal/engine"
)

func main() {
	file := flag.String("file", "", "Go file to inspect or update")
	patchFile := flag.String("patch", "", "JSON patch instruction")
	write := flag.Bool("write", false, "write the validated candidate to source")
	brief := flag.Bool("brief", false, "context: omit doc comments and signatures")
	typecheck := flag.Bool("typecheck", false, "context: also run the type-checker")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: goai [patch|context|check] -file file.go [-patch patch.json] [-write] [-brief] [-typecheck]")
		flag.PrintDefaults()
	}
	flag.Parse()

	mode := "patch"
	if flag.NArg() > 0 {
		mode = flag.Arg(0)
		if flag.NArg() > 1 {
			usageError("GOAI-USAGE-002", "unexpected arguments: "+fmt.Sprint(flag.Args()[1:]))
		}
	}
	if *file == "" {
		usageError("GOAI-USAGE-001", "usage: goai [patch|context|check] -file file.go [-patch patch.json] [-write]")
	}
	source, err := os.ReadFile(*file)
	if err != nil {
		usageError("GOAI-IO-004", err.Error())
	}

	switch mode {
	case "context":
		out := engine.Outline(*file, source, engine.OutlineOptions{Brief: *brief, Typecheck: *typecheck})
		printJSON(out)
		if !out.OK {
			os.Exit(2)
		}
	case "check":
		out := engine.Check(*file, source)
		printJSON(out)
		if !out.OK {
			os.Exit(2)
		}
	case "patch":
		runPatch(*file, *patchFile, source, *write)
	default:
		usageError("GOAI-USAGE-003", "unknown mode "+mode+": expected patch, context, or check")
	}
}

func runPatch(path, patchPath string, original []byte, write bool) {
	if patchPath == "" {
		usageError("GOAI-USAGE-001", "patch mode needs -patch patch.json")
	}
	patchBytes, err := os.ReadFile(patchPath)
	if err != nil {
		usageError("GOAI-IO-003", err.Error())
	}
	parsed, err := engine.ParsePatch(patchBytes)
	if err != nil {
		usageError("GOAI-PATCH-001", err.Error())
	}
	out := engine.Apply(path, original, parsed)
	if !out.OK {
		printJSON(out)
		os.Exit(2)
	}
	if write {
		if err := engine.WriteAtomic(path, original, out.UpdatedSource); err != nil {
			out.OK = false
			out.Diagnostics = append(out.Diagnostics, engine.Diagnostic{Code: "GOAI-WRITE-001", Message: err.Error(), Hint: "re-read the file; it changed after validation", Retryable: true})
			printJSON(out)
			os.Exit(3)
		}
		out.Written = true
		out.UpdatedSource = ""
		out.NextActions = engine.WithoutKind(out.NextActions, "apply_write")
	}
	printJSON(out)
}

func usageError(code, message string) {
	printJSON(engine.Result{
		Protocol:    engine.Protocol,
		OK:          false,
		Diagnostics: []engine.Diagnostic{{Code: code, Message: message, Retryable: false}},
	})
	os.Exit(1)
}

func printJSON(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(b))
}
