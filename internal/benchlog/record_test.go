package benchlog

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func valid() Run {
	sha := strings.Repeat("a", 64)
	return Run{SchemaVersion: Version, RunID: "run-1", TaskID: "task-1", Category: "micro_logic", Modality: Intent, Replicate: 1,
		Model:      Model{Provider: "test-provider", ID: "test-model", Revision: "pinned-model", Temperature: 0},
		Provenance: Provenance{DatasetSHA256: sha, TaskSHA256: sha, PromptSHA256: sha, ToolPolicySHA256: sha, HarnessCommit: "a123", BaseCommit: "b456"}, TokenBudget: 10000, WallTimeMS: 200,
		UsageSource: "provider", ModelCalls: []ModelCall{{ID: "1", InputTokens: 100, OutputTokens: 12, CachedInputTokens: 20, ReasoningOutputTokens: 2, LatencyMS: 50}},
		ToolEvents:   []ToolEvent{{Name: "candidate_catalog", OutputBytes: 300, EstimatedOutputTokens: ptr(70), FedToModel: true, LatencyMS: 2}},
		EditAttempts: []EditAttempt{{Index: 1, AcceptedByTool: true, PublicTests: "pass"}},
		Coverage:     Coverage{Status: "supported", CandidateCount: 1}, Outcome: Outcome{PublicTests: "pass", HiddenTests: "pass", EndReason: "completed"}}
}
func ptr(n uint64) *uint64 { return &n }
func TestValidAndTotals(t *testing.T) {
	r := valid()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	in, out, ok := r.Totals()
	if !ok || in != 100 || out != 12 {
		t.Fatal(in, out, ok)
	}
}
func TestRejectInvalidRuns(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Run)
	}{
		{"missing provenance", func(r *Run) { r.Provenance.TaskSHA256 = "" }},
		{"double counting cached input", func(r *Run) { r.ModelCalls[0].CachedInputTokens = 101 }},
		{"unknown outcome", func(r *Run) { r.Outcome.HiddenTests = "model_says_pass" }},
		{"missing coverage", func(r *Run) { r.Coverage.Status = "not_applicable" }},
		{"fallback without reason", func(r *Run) { r.Coverage.FallbackToText = true }},
		{"unknown schema", func(r *Run) { r.SchemaVersion = "goai.bench.v0.2" }},
		{"repeat attempt index", func(r *Run) { r.EditAttempts = append(r.EditAttempts, EditAttempt{Index: 1, PublicTests: "fail"}) }},
		{"missing model call", func(r *Run) { r.ModelCalls = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := valid()
			tc.change(&r)
			if err := r.Validate(); err == nil {
				t.Fatal("invalid record accepted")
			}
		})
	}
}
func TestReadJSONLRejectDuplicatesUnknownFieldsAndExtraObjects(t *testing.T) {
	r := valid()
	b, _ := json.Marshal(r)
	if runs, err := ReadJSONL(bytes.NewReader(append(b, '\n'))); err != nil || len(runs) != 1 {
		t.Fatalf("%v %#v", err, runs)
	}
	for _, data := range []string{string(b) + "\n" + string(b) + "\n", strings.Replace(string(b), "\"run_id\":", "\"unexpected\":true,\"run_id\":", 1) + "\n", string(b) + " {}\n"} {
		if _, err := ReadJSONL(strings.NewReader(data)); err == nil {
			t.Fatal("invalid JSONL accepted")
		}
	}
}
func TestUnavailableUsageNotZero(t *testing.T) {
	r := valid()
	r.UsageSource = "unavailable"
	r.ModelCalls = nil
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	_, _, ok := r.Totals()
	if ok {
		t.Fatal("missing metrics reported as zero")
	}
}
