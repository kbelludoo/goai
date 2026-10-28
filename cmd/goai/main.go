// Command goai exposes the engine to a caller that is not a human: every mode
// prints one JSON envelope on stdout, and the exit code is the primary signal.
//
//	goai patch   -file f.go -patch p.json [-write]
//	goai context -file f.go [-brief] [-typecheck]
//	goai check   -file f.go
//	goai sandbox [-root cgroup2-dir] [-limits profile] [-probe trusted-binary]
//
// The mode is the first positional argument; omitting it keeps the original
// `goai -file f.go -patch p.json` invocation working.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kbelludoo/goai/internal/engine"
	"github.com/kbelludoo/goai/internal/sandboxpolicy"
)

const usageLine = "usage: goai [patch|context|check] -file file.go [-patch patch.json] [-write] [-brief] [-typecheck] | goai sandbox [-root dir] [-probe binary]"

// options is the parsed command line. It exists as a value so that mode and
// flag interaction is testable without exec'ing the binary.
type options struct {
	mode      string
	file      string
	patch     string
	write     bool
	brief     bool
	typecheck bool
	root      string
	probe     string
	limits    string
	enable    bool
}

// usageErr carries a stable diagnostic code to the JSON envelope.
type usageErr struct {
	code    string
	message string
}

func (e *usageErr) Error() string { return e.message }

// parseArgs accepts the mode either before or after nothing at all: the first
// non-flag argument selects the mode, and the remaining flags are parsed after
// it. Parsing flags first would stop at the mode and silently ignore -file.
func parseArgs(args []string) (options, error) {
	opts := options{mode: "patch"}
	fs := flag.NewFlagSet("goai", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, usageLine)
		fs.PrintDefaults()
	}
	file := fs.String("file", "", "Go file to inspect or update")
	patch := fs.String("patch", "", "JSON patch instruction")
	write := fs.Bool("write", false, "write the validated candidate to source")
	brief := fs.Bool("brief", false, "context: omit doc comments and signatures")
	typecheck := fs.Bool("typecheck", false, "context: also run the type-checker")
	rootFlag := fs.String("root", "", "sandbox: delegated, process-free cgroup v2 directory")
	probeFlag := fs.String("probe", "", "sandbox: trusted absolute binary used to prove atomic placement")
	limitsFlag := fs.String("limits", "", "sandbox: policy profile, e.g. 512MiB/50%/100")
	enableFlag := fs.Bool("enable", false, "sandbox: enable cpu/memory/pids controllers on a process-free root (mutates host)")

	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		opts.mode = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return opts, err
		}
		return opts, &usageErr{code: "GOAI-USAGE-004", message: err.Error()}
	}
	if fs.NArg() > 0 {
		return opts, &usageErr{code: "GOAI-USAGE-002", message: "unexpected arguments: " + strings.Join(fs.Args(), " ")}
	}
	opts.file, opts.patch, opts.write, opts.brief, opts.typecheck = *file, *patch, *write, *brief, *typecheck
	opts.root, opts.probe, opts.limits = *rootFlag, *probeFlag, *limitsFlag
	opts.enable = *enableFlag
	switch opts.mode {
	case "patch", "context", "check":
	case "sandbox":
		// sandbox mode reads no file, so -file is not required.
		if opts.file != "" {
			return opts, &usageErr{code: "GOAI-USAGE-002", message: "sandbox mode does not take -file"}
		}
		return opts, nil
	default:
		return opts, &usageErr{code: "GOAI-USAGE-003", message: "unknown mode " + opts.mode + ": expected patch, context, check, or sandbox"}
	}
	if opts.file == "" {
		return opts, &usageErr{code: "GOAI-USAGE-001", message: usageLine}
	}
	return opts, nil
}

func main() {
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		var usage *usageErr
		if errors.As(err, &usage) {
			emit(engine.Result{
				Protocol:    engine.Protocol,
				Diagnostics: []engine.Diagnostic{{Code: usage.code, Message: usage.message}},
			})
			os.Exit(1)
		}
		os.Exit(0) // flag.ErrHelp already printed usage
	}
	if opts.mode == "sandbox" {
		runSandbox(opts)
		return
	}
	source, err := os.ReadFile(opts.file)
	if err != nil {
		emit(engine.Result{
			Protocol:    engine.Protocol,
			Diagnostics: []engine.Diagnostic{{Code: "GOAI-IO-004", Message: err.Error()}},
		})
		os.Exit(1)
	}
	switch opts.mode {
	case "context":
		out := engine.Outline(opts.file, source, engine.OutlineOptions{Brief: opts.brief, Typecheck: opts.typecheck})
		emit(out)
		if !out.OK {
			os.Exit(2)
		}
	case "check":
		out := engine.Check(opts.file, source)
		emit(out)
		if !out.OK {
			os.Exit(2)
		}
	default:
		runPatch(opts, source)
	}
}

func runPatch(opts options, original []byte) {
	if opts.patch == "" {
		emit(engine.Result{
			Protocol:    engine.Protocol,
			Diagnostics: []engine.Diagnostic{{Code: "GOAI-USAGE-001", Message: "patch mode needs -patch patch.json"}},
		})
		os.Exit(1)
	}
	patchBytes, err := os.ReadFile(opts.patch)
	if err != nil {
		emit(engine.Result{
			Protocol:    engine.Protocol,
			Diagnostics: []engine.Diagnostic{{Code: "GOAI-IO-003", Message: err.Error()}},
		})
		os.Exit(1)
	}
	parsed, err := engine.ParsePatch(patchBytes)
	if err != nil {
		emit(engine.Result{
			Protocol:    engine.Protocol,
			Diagnostics: []engine.Diagnostic{{Code: "GOAI-PATCH-001", Message: err.Error()}},
		})
		os.Exit(1)
	}
	out := engine.Apply(opts.file, original, parsed)
	if !out.OK {
		emit(out)
		os.Exit(2)
	}
	if opts.write {
		if err := engine.WriteAtomic(opts.file, original, out.UpdatedSource); err != nil {
			out.OK = false
			out.Diagnostics = append(out.Diagnostics, engine.Diagnostic{
				Code:      "GOAI-WRITE-001",
				Message:   err.Error(),
				Hint:      "re-read the file; it changed after validation",
				Retryable: true,
			})
			emit(out)
			os.Exit(3)
		}
		out.Written = true
		out.UpdatedSource = ""
		out.NextActions = engine.WithoutKind(out.NextActions, "apply_write")
	}
	emit(out)
}

// runSandbox prints a fail-closed verdict. A denied decision exits 2 so a
// caller script cannot mistake "cannot prove containment" for success.
func runSandbox(opts options) {
	root := opts.root
	if root == "" {
		root = os.Getenv("GOAI_DELEGATION_ROOT")
	}
	limits, err := sandboxpolicy.ParseLimits(opts.limits)
	if err != nil {
		emit(sandboxpolicy.Decision{
			Protocol: sandboxpolicy.Protocol,
			Mode:     "sandbox",
			Allowed:  false,
			Checks: []sandboxpolicy.Check{{
				Name:   "limits",
				Status: sandboxpolicy.StatusFail,
				Code:   "GOAI-CGROUP-003",
				Detail: err.Error(),
			}},
			Reasons: []string{err.Error()},
		})
		os.Exit(1)
	}
	if opts.enable {
		// Explicit host mutation: enabling controllers is how a delegated but
		// not-yet-enabled root becomes usable. Report it as its own check so a
		// denial cannot hide which step failed.
		if err := sandboxpolicy.Enable(root); err != nil {
			emit(sandboxpolicy.Decision{
				Protocol: sandboxpolicy.Protocol,
				Mode:     "sandbox",
				Root:     root,
				Allowed:  false,
				Checks: []sandboxpolicy.Check{{
					Name:   "enable_controllers",
					Status: sandboxpolicy.StatusFail,
					Code:   "GOAI-CGROUP-002",
					Detail: err.Error(),
				}},
				Reasons: []string{err.Error()},
			})
			os.Exit(2)
		}
	}
	if opts.probe == "" {
		decision := sandboxpolicy.Evaluate(root, limits)
		emit(decision)
		if !decision.Allowed {
			os.Exit(2)
		}
		return
	}
	decision, probeErr := sandboxpolicy.ProbeAtomicPlacement(root, limits, opts.probe)
	emit(decision)
	if probeErr != nil || !decision.Allowed {
		if probeErr != nil {
			fmt.Fprintln(os.Stderr, "probe:", probeErr)
		}
		os.Exit(2)
	}
}

func emit(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(b))
}
