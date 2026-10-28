package benchdriver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kbelludoo/goai/internal/benchlog"
)

type scriptedModel struct {
	replies      []Reply
	calls        int
	sawHidden    bool
	expectedTool string
}

func (s *scriptedModel) Next(_ context.Context, h []Message, specs []ToolSpec) (Reply, error) {
	for _, m := range h {
		if strings.Contains(m.Content, "SECRET_HIDDEN_TEST") {
			s.sawHidden = true
		}
	}
	if s.expectedTool != "" && !isAllowed(specs, s.expectedTool) {
		return Reply{}, errors.New("tool hidden from policy")
	}
	if s.calls >= len(s.replies) {
		return Reply{}, errors.New("script exhausted")
	}
	x := s.replies[s.calls]
	s.calls++
	return x, nil
}

type scriptedExecutor struct {
	names   []string
	calls   []Call
	results map[string]ToolResult
}

func (s *scriptedExecutor) Execute(_ context.Context, c Call) (ToolResult, error) {
	s.names = append(s.names, c.Name)
	s.calls = append(s.calls, c)
	return s.results[c.Name], nil
}
func tool(name string) Reply {
	return Reply{UsageReported: true, InputTokens: 20, OutputTokens: 5, Call: &Call{Name: name, Arguments: json.RawMessage(`{"path":"wallet.go"}`)}}
}
func ending() Reply {
	return Reply{UsageReported: true, InputTokens: 20, OutputTokens: 3, Text: "done"}
}
func digest(s string) string { a := sha256.Sum256([]byte(s)); return hex.EncodeToString(a[:]) }
func config(m benchlog.Modality) Config {
	return Config{
		RunID: "run-1", Replicate: 1, Modality: m, MaxTurns: 8, TokenBudget: 1000,
		Model:      benchlog.Model{Provider: "script", ID: "fixed-fixture", Revision: "v1", Temperature: 0},
		Provenance: benchlog.Provenance{DatasetSHA256: digest("dataset"), TaskSHA256: digest("task"), HarnessCommit: "h", BaseCommit: "base"},
	}
}
func task() Task {
	return Task{ID: "bug-1", Category: "micro_logic", Issue: "wallet withdrawal incorrect", PublicContext: "wallet.go public code"}
}
func TestFourModalitiesSameAgentLoopAndNoHiddenJudge(t *testing.T) {
	tests := []struct {
		mod  benchlog.Modality
		tool string
	}{
		{benchlog.Text, "apply_text_patch"}, {benchlog.Structured, "apply_text_patch"},
		{benchlog.AST, "apply_ast_mutation"}, {benchlog.Intent, "choose_candidate"},
	}
	for _, tc := range tests {
		t.Run(string(tc.mod), func(t *testing.T) {
			replies := []Reply{tool(tc.tool), tool("run_tests"), ending()}
			if tc.mod == benchlog.Intent {
				replies = []Reply{tool("request_catalog"), tool(tc.tool), tool("run_tests"), ending()}
			}
			model := &scriptedModel{replies: replies, expectedTool: tc.tool}
			executor := &scriptedExecutor{results: map[string]ToolResult{
				tc.tool:           {Output: "accepted", Accepted: true, CoverageStatus: "supported", CandidateCount: 1},
				"request_catalog": {Output: "catalog", Accepted: true, CoverageStatus: "supported", CandidateCount: 1},
				"run_tests":       {Output: "pass", PublicTests: "pass"},
			}}
			run, err := Run(context.Background(), config(tc.mod), task(), model, executor)
			if err != nil {
				t.Fatal(err)
			}
			if model.sawHidden {
				t.Fatal("hidden judge leaked to model")
			}
			if run.Outcome.HiddenTests != "not_run" || run.Outcome.PublicTests != "pass" || run.Outcome.EndReason != "completed" {
				t.Fatalf("unexpected outcome %+v", run.Outcome)
			}
			if len(run.EditAttempts) != 1 || run.EditAttempts[0].PublicTests != "pass" {
				t.Fatal("attempt tracking failed")
			}
			in, out, ok := run.Totals()
			expectedInput, expectedOutput := uint64(60), uint64(13)
			if tc.mod == benchlog.Intent {
				expectedInput = 80
				expectedOutput = 18
			}
			if !ok || in != expectedInput || out != expectedOutput {
				t.Fatalf("tokens: %d,%d,%t", in, out, ok)
			}
			expectedTools := 2
			if tc.mod == benchlog.Intent {
				expectedTools = 3
			}
			if len(run.ToolEvents) != expectedTools || len(executor.names) != expectedTools {
				t.Fatalf("tool count wrong: %+v", run.ToolEvents)
			}
			if tc.mod == benchlog.Text || tc.mod == benchlog.Structured {
				if run.Coverage.Status != "not_applicable" {
					t.Fatal("incorrect text coverage")
				}
			} else if run.Coverage.Status != "supported" {
				t.Fatal("missing structured coverage")
			}
		})
	}
}
func TestFallbackIncludedAndUnsupportedNotHidden(t *testing.T) {
	c := config(benchlog.Intent)
	c.AllowTextFallback = true
	model := &scriptedModel{replies: []Reply{tool("request_catalog"), tool("fallback_to_text_patch"), ending()}}
	ex := &scriptedExecutor{results: map[string]ToolResult{
		"request_catalog":        {Output: "unsupported", CoverageStatus: "unsupported", CandidateCount: 0},
		"fallback_to_text_patch": {Output: "patch accepted", Accepted: true},
	}}
	r, err := Run(context.Background(), c, task(), model, ex)
	if err != nil {
		t.Fatal(err)
	}
	if r.Coverage.Status != "unsupported" || !r.Coverage.FallbackToText || r.Coverage.FallbackReason == "" {
		t.Fatalf("missing true fallback: %+v", r.Coverage)
	}
}
func TestForbiddenToolNeverInvokesExecutor(t *testing.T) {
	model := &scriptedModel{replies: []Reply{tool("run_hidden_tests"), ending()}}
	ex := &scriptedExecutor{}
	run, err := Run(context.Background(), config(benchlog.Text), task(), model, ex)
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.names) != 0 || run.Outcome.HiddenTests != "not_run" || run.ToolEvents[0].Name != "denied:run_hidden_tests" {
		t.Fatal("forbidden tool reached executor")
	}
}
func TestMissingUsageNotZeroTokens(t *testing.T) {
	m := &scriptedModel{replies: []Reply{{Text: "done", UsageReported: false}}}
	r, err := Run(context.Background(), config(benchlog.Text), task(), m, &scriptedExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, available := r.Totals()
	if available || r.UsageSource != "unavailable" || len(r.ModelCalls) > 0 {
		t.Fatal("missing model usage should not look like 0")
	}
}
func TestBadArgumentsBlockedBeforeExecutor(t *testing.T) {
	m := &scriptedModel{replies: []Reply{{UsageReported: true, Call: &Call{Name: "apply_text_patch", Arguments: json.RawMessage(`not-json`)}}, ending()}}
	ex := &scriptedExecutor{}
	r, err := Run(context.Background(), config(benchlog.Text), task(), m, ex)
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.calls) > 0 || len(r.ToolEvents) != 1 {
		t.Fatalf("unvalidated arguments executed: %+v", r.ToolEvents)
	}
}
func TestModelFailuresDoNotCreateFakePass(t *testing.T) {
	m := &scriptedModel{replies: nil}
	r, err := Run(context.Background(), config(benchlog.Text), task(), m, &scriptedExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Outcome.EndReason != "infra_error" || r.Outcome.HiddenTests != "not_run" {
		t.Fatal("invented outcome")
	}
}
func TestNoShellOrModelProviderBuiltIntoDriver(t *testing.T) {
	if _, err := Run(context.Background(), config(benchlog.Text), task(), nil, &scriptedExecutor{}); !errors.Is(err, ErrBadConfig) {
		t.Fatal("nil model allowed")
	}
}

func TestUnsupportedWithoutFallbackIsNotSuccess(t *testing.T) {
	model := &scriptedModel{replies: []Reply{tool("request_catalog"), ending()}}
	ex := &scriptedExecutor{results: map[string]ToolResult{"request_catalog": {Output: "no candidate", Accepted: true, CoverageStatus: "unsupported"}}}
	r, err := Run(context.Background(), config(benchlog.Intent), task(), model, ex)
	if err != nil {
		t.Fatal(err)
	}
	if r.Outcome.EndReason != "unsupported" || r.Coverage.Status != "unsupported" || r.Outcome.HiddenTests != "not_run" {
		t.Fatalf("incorrect unsupported disposition: %+v %+v", r.Coverage, r.Outcome)
	}
}
func TestChooseWithoutCatalogRejected(t *testing.T) {
	model := &scriptedModel{replies: []Reply{tool("choose_candidate"), ending()}}
	ex := &scriptedExecutor{}
	r, err := Run(context.Background(), config(benchlog.Intent), task(), model, ex)
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.calls) != 0 || len(r.EditAttempts) != 0 || r.ToolEvents[0].Name != "denied:choose_candidate" {
		t.Fatalf("catalog bypass: %+v", r)
	}
}
func TestPromptAndToolHashesAreReproducible(t *testing.T) {
	a := &scriptedModel{replies: []Reply{ending()}}
	b := &scriptedModel{replies: []Reply{ending()}}
	c := config(benchlog.Text)
	first, err := Run(context.Background(), c, task(), a, &scriptedExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Run(context.Background(), c, task(), b, &scriptedExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	if first.Provenance.PromptSHA256 != second.Provenance.PromptSHA256 || first.Provenance.ToolPolicySHA256 != second.Provenance.ToolPolicySHA256 {
		t.Fatal("nondeterministic hashes")
	}
	another := task()
	another.Issue = "different issue"
	third, err := Run(context.Background(), c, another, &scriptedModel{replies: []Reply{ending()}}, &scriptedExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	if first.Provenance.PromptSHA256 == third.Provenance.PromptSHA256 {
		t.Fatal("prompt hash ignores issue")
	}
}
