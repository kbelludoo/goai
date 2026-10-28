// Package benchdriver runs a modality-controlled LLM tool loop. It NEVER runs
// commands or grades hidden tests: both model and tool execution are injected.
// In particular, model text is not evidence that public or hidden tests passed.
package benchdriver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kbelludoo/goai/internal/benchlog"
)

const SystemPrompt = "You are a Go software engineer. Fix the provided issue using the available tools. Inspect the code, run the public tests, and minimize attempts and tokens. Report uncertainty. Do not assume that your own claims constitute test evidence."

// Messages are model-visible. Hidden tests and private judge artifacts are
// deliberately absent from the input types of the model and tool interfaces.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type ToolSpec struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}
type Call struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}
type Reply struct {
	Text                  string
	Call                  *Call
	InputTokens           uint64
	OutputTokens          uint64
	CachedInputTokens     uint64
	ReasoningOutputTokens uint64
	// UsageReported must reflect API response metadata, never model prose.
	UsageReported bool
}
type Model interface {
	Next(context.Context, []Message, []ToolSpec) (Reply, error)
}

// ToolExecutor must be a trusted, separately isolated harness. The model can
// suggest calls but CANNOT provide ToolResult or choose hidden test outcomes.
type ToolExecutor interface {
	Execute(context.Context, Call) (ToolResult, error)
}
type ToolResult struct {
	Output    string
	Accepted  bool
	ErrorCode string
	// PublicTests is an observed status from the trusted executor only.
	PublicTests    string // pass, fail, not_run, or empty
	CoverageStatus string // supported, unsupported, unknown, or empty
	CandidateCount int
}
type Task struct {
	ID       string
	Category string
	Issue    string
	// Non-secret public context only: NEVER insert held-out tests here.
	PublicContext string
}
type Config struct {
	RunID             string
	Replicate         int
	Modality          benchlog.Modality
	Model             benchlog.Model
	Provenance        benchlog.Provenance
	TokenBudget       uint64
	MaxTurns          int
	AllowTextFallback bool
}

var ErrBadConfig = errors.New("benchdriver: invalid configuration")

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func policy(m benchlog.Modality, fallback bool) ([]ToolSpec, error) {
	core := []ToolSpec{{"read_file", "Read a public repository file"}, {"run_tests", "Run public tests using the trusted isolated executor"}}
	switch m {
	case benchlog.Text:
		return append(core, ToolSpec{"apply_text_patch", "Submit unified diff"}), nil
	case benchlog.Structured:
		return append(core, ToolSpec{"apply_text_patch", "Submit unified diff; compiler feedback is structured by executor"}), nil
	case benchlog.AST:
		core = append(core, ToolSpec{"apply_ast_mutation", "Submit one version-bound structured AST mutation"})
	case benchlog.Intent:
		core = append(core, ToolSpec{"request_catalog", "Request a version-scoped, bounded candidate catalogue"}, ToolSpec{"choose_candidate", "Choose previously issued candidate ID"})
	default:
		return nil, ErrBadConfig
	}
	if fallback {
		core = append(core, ToolSpec{"fallback_to_text_patch", "Explicitly abandon structured editing and submit a textual diff"})
	}
	return core, nil
}
func validPublic(s string) bool { return s == "" || s == "not_run" || s == "fail" || s == "pass" }
func validCoverage(s string) bool {
	return s == "" || s == "supported" || s == "unsupported" || s == "unknown"
}
func isEdit(name string) bool {
	return name == "apply_text_patch" || name == "apply_ast_mutation" || name == "choose_candidate" || name == "fallback_to_text_patch"
}
func isAllowed(tools []ToolSpec, name string) bool {
	for _, t := range tools {
		if t.Name == name {
			return true
		}
	}
	return false
}
func cloned(history []Message) []Message { return append([]Message(nil), history...) }

// Run executes a bounded tool loop; it never calls hidden-test adjudication.
// Every modality uses SystemPrompt and the same Model implementation. Only
// tools/feedback contracts change. Timing and tokens include every model call.
func Run(ctx context.Context, cfg Config, task Task, brain Model, tools ToolExecutor) (benchlog.Run, error) {
	specs, err := policy(cfg.Modality, cfg.AllowTextFallback)
	if err != nil {
		return benchlog.Run{}, err
	}
	if brain == nil || tools == nil || task.ID == "" || task.Issue == "" || cfg.RunID == "" || cfg.MaxTurns < 1 || cfg.MaxTurns > 100 || cfg.TokenBudget == 0 {
		return benchlog.Run{}, ErrBadConfig
	}
	if cfg.Modality == benchlog.Text || cfg.Modality == benchlog.Structured {
		cfg.AllowTextFallback = false
	}
	start := time.Now()
	specsJSON, _ := json.Marshal(specs)
	cfg.Provenance.ToolPolicySHA256 = sha(string(specsJSON))
	r := benchlog.Run{
		SchemaVersion: benchlog.Version, RunID: cfg.RunID, TaskID: task.ID, Category: task.Category,
		Modality: cfg.Modality, Replicate: cfg.Replicate, Model: cfg.Model, Provenance: cfg.Provenance,
		TokenBudget: cfg.TokenBudget, UsageSource: "unavailable", Coverage: benchlog.Coverage{Status: "unknown"},
		Outcome: benchlog.Outcome{PublicTests: "not_run", HiddenTests: "not_run", EndReason: "budget_exhausted"},
	}
	if cfg.Modality == benchlog.Text || cfg.Modality == benchlog.Structured {
		r.Coverage.Status = "not_applicable"
	}
	history := []Message{{Role: "system", Content: SystemPrompt}, {Role: "user", Content: "Issue:\n" + task.Issue + "\n\nPublic context:\n" + task.PublicContext}}
	promptWire, _ := json.Marshal(history)
	r.Provenance.PromptSHA256 = sha(string(promptWire))
	var total uint64
	catalogReady := false
	final := func() (benchlog.Run, error) {
		r.WallTimeMS = time.Since(start).Milliseconds()
		if err := r.Validate(); err != nil {
			return benchlog.Run{}, fmt.Errorf("invalid harness record: %w", err)
		}
		return r, nil
	}
	for step := 1; step <= cfg.MaxTurns; step++ {
		if err := ctx.Err(); err != nil {
			r.Outcome.EndReason = "timeout"
			return final()
		}
		t := time.Now()
		reply, e := brain.Next(ctx, cloned(history), append([]ToolSpec(nil), specs...))
		elapsed := time.Since(t).Milliseconds()
		if e != nil {
			r.Outcome.EndReason = "infra_error"
			return final()
		}
		// Do not report fake zero token usage if provider does not supply usage.
		if !reply.UsageReported {
			r.UsageSource = "unavailable"
			r.ModelCalls = nil
		} else if r.UsageSource == "provider" || step == 1 {
			r.UsageSource = "provider"
			r.ModelCalls = append(r.ModelCalls, benchlog.ModelCall{ID: fmt.Sprintf("%d", step), InputTokens: reply.InputTokens, OutputTokens: reply.OutputTokens, CachedInputTokens: reply.CachedInputTokens, ReasoningOutputTokens: reply.ReasoningOutputTokens, LatencyMS: elapsed})
		}
		total += reply.InputTokens + reply.OutputTokens
		if total > cfg.TokenBudget {
			r.Outcome.EndReason = "budget_exhausted"
			return final()
		}
		if reply.Call == nil {
			r.Outcome.EndReason = "completed"
			if r.Coverage.Status == "unsupported" && !r.Coverage.FallbackToText {
				r.Outcome.EndReason = "unsupported"
			}
			return final()
		}
		call := *reply.Call
		if !isAllowed(specs, call.Name) || (call.Name == "choose_candidate" && !catalogReady) {
			// Model is NEVER allowed to gain access to an unadvertised tool.
			history = append(history, Message{Role: "assistant", Content: "tool:" + call.Name}, Message{Role: "tool", Content: "GOAI-TOOL-DENIED"})
			r.ToolEvents = append(r.ToolEvents, benchlog.ToolEvent{Name: "denied:" + call.Name, OutputBytes: uint64(len("GOAI-TOOL-DENIED")), FedToModel: true})
			continue
		}
		if len(call.Arguments) > 32*1024 || !json.Valid(call.Arguments) {
			history = append(history, Message{Role: "assistant", Content: "tool:" + call.Name}, Message{Role: "tool", Content: "GOAI-TOOL-BAD-ARGS"})
			r.ToolEvents = append(r.ToolEvents, benchlog.ToolEvent{Name: call.Name, OutputBytes: uint64(len("GOAI-TOOL-BAD-ARGS")), FedToModel: true})
			continue
		}
		t = time.Now()
		out, e := tools.Execute(ctx, call)
		elapsed = time.Since(t).Milliseconds()
		if e != nil {
			r.Outcome.EndReason = "infra_error"
			return final()
		}
		if !validPublic(out.PublicTests) || !validCoverage(out.CoverageStatus) || out.CandidateCount < 0 {
			r.Outcome.EndReason = "infra_error"
			return final()
		}
		// Bounded feedback prevents a tool from filling the context uncontrollably.
		if len(out.Output) > 64*1024 {
			out.Output = out.Output[:64*1024] + "\n[TRUNCATED]"
		}
		r.ToolEvents = append(r.ToolEvents, benchlog.ToolEvent{Name: call.Name, OutputBytes: uint64(len(out.Output)), FedToModel: true, LatencyMS: elapsed})
		history = append(history, Message{Role: "assistant", Content: "tool:" + call.Name + " " + string(call.Arguments)}, Message{Role: "tool", Content: out.Output})
		if call.Name == "request_catalog" && out.Accepted && out.CoverageStatus == "supported" && out.CandidateCount > 0 {
			catalogReady = true
		}
		if (cfg.Modality == benchlog.AST || cfg.Modality == benchlog.Intent) && out.CoverageStatus != "" {
			r.Coverage.Status = out.CoverageStatus
			r.Coverage.CandidateCount = out.CandidateCount
		}
		if call.Name == "fallback_to_text_patch" {
			r.Coverage.FallbackToText = true
			r.Coverage.FallbackReason = "explicit_model_fallback"
		}
		if isEdit(call.Name) {
			a := benchlog.EditAttempt{Index: len(r.EditAttempts) + 1, AcceptedByTool: out.Accepted, PublicTests: "not_run", LatencyMS: elapsed, ErrorCode: out.ErrorCode}
			r.EditAttempts = append(r.EditAttempts, a)
		}
		if call.Name == "run_tests" && out.PublicTests != "" {
			r.Outcome.PublicTests = out.PublicTests
			if len(r.EditAttempts) > 0 {
				r.EditAttempts[len(r.EditAttempts)-1].PublicTests = out.PublicTests
			}
		}
	}
	return final()
}
