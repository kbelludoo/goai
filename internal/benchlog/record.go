// Package benchlog defines strictly validated, model-agnostic benchmark results.
// A JSONL row is one complete task x modality x replicate run, recorded by the
// trusted harness, not by the agent or by the model's own claim of success.
package benchlog

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const Version = "goai.bench.v0.1"
const MaxLineBytes = 4 << 20

type Modality string

const (
	Text       Modality = "m1_text"
	Structured Modality = "m2_text_diagnostics"
	AST        Modality = "m3_ast"
	Intent     Modality = "m4_intent_catalog"
)

type Model struct {
	Provider    string  `json:"provider"`
	ID          string  `json:"id"`
	Revision    string  `json:"revision"`
	Temperature float64 `json:"temperature"`
	Seed        *int64  `json:"seed,omitempty"`
}
type Provenance struct {
	DatasetSHA256    string `json:"dataset_sha256"`
	TaskSHA256       string `json:"task_sha256"`
	PromptSHA256     string `json:"prompt_sha256"`
	ToolPolicySHA256 string `json:"tool_policy_sha256"`
	HarnessCommit    string `json:"harness_commit"`
	BaseCommit       string `json:"base_commit"`
}

// A model call has provider-reported token counts. CachedInputTokens is a
// SUBSET of InputTokens; ReasoningOutputTokens is a SUBSET of OutputTokens.
// Tool responses consumed by later calls are already included in their input.
type ModelCall struct {
	ID                    string `json:"id"`
	InputTokens           uint64 `json:"input_tokens"`
	OutputTokens          uint64 `json:"output_tokens"`
	CachedInputTokens     uint64 `json:"cached_input_tokens"`
	ReasoningOutputTokens uint64 `json:"reasoning_output_tokens"`
	LatencyMS             int64  `json:"latency_ms"`
}

// Tool output tokens are diagnostic estimates and MUST NOT be added to
// provider input/output totals (that would double-count tool responses).
type ToolEvent struct {
	Name                  string  `json:"name"`
	OutputBytes           uint64  `json:"output_bytes"`
	EstimatedOutputTokens *uint64 `json:"estimated_output_tokens,omitempty"`
	FedToModel            bool    `json:"fed_to_model"`
	LatencyMS             int64   `json:"latency_ms"`
}
type EditAttempt struct {
	Index          int    `json:"index"`
	AcceptedByTool bool   `json:"accepted_by_tool"`
	PublicTests    string `json:"public_tests"` // pass, fail, not_run
	LatencyMS      int64  `json:"latency_ms"`
	ErrorCode      string `json:"error_code,omitempty"`
	ErrorLogSHA256 string `json:"error_log_sha256,omitempty"` // log stored outside agent-facing context
}
type Coverage struct {
	Status         string `json:"status"` // not_applicable, supported, unsupported, unknown
	CandidateCount int    `json:"candidate_count"`
	FallbackToText bool   `json:"fallback_to_text"`
	FallbackReason string `json:"fallback_reason,omitempty"`
}
type Outcome struct {
	PublicTests string `json:"public_tests"` // pass, fail, not_run
	HiddenTests string `json:"hidden_tests"` // pass, fail, not_run
	EndReason   string `json:"end_reason"`   // completed, unsupported, timeout, infra_error, budget_exhausted
}
type Run struct {
	SchemaVersion string        `json:"schema_version"`
	RunID         string        `json:"run_id"`
	TaskID        string        `json:"task_id"`
	Category      string        `json:"category"` // micro_logic, structural, domain
	Modality      Modality      `json:"modality"`
	Replicate     int           `json:"replicate"`
	Model         Model         `json:"model"`
	Provenance    Provenance    `json:"provenance"`
	TokenBudget   uint64        `json:"token_budget"`
	WallTimeMS    int64         `json:"wall_time_ms"`
	UsageSource   string        `json:"usage_source"` // provider, estimated, unavailable
	ModelCalls    []ModelCall   `json:"model_calls"`
	ToolEvents    []ToolEvent   `json:"tool_events"`
	EditAttempts  []EditAttempt `json:"edit_attempts"`
	Coverage      Coverage      `json:"coverage"`
	Outcome       Outcome       `json:"outcome"`
}

func oneOf(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}
func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && s == strings.ToLower(s)
}
func validTest(s string) bool { return oneOf(s, "pass", "fail", "not_run") }
func (r Run) Validate() error {
	if r.SchemaVersion != Version {
		return fmt.Errorf("unsupported schema_version %q", r.SchemaVersion)
	}
	if r.RunID == "" || r.TaskID == "" || r.Replicate < 1 {
		return errors.New("missing run_id/task_id or invalid replicate")
	}
	if !oneOf(r.Category, "micro_logic", "structural", "domain") {
		return fmt.Errorf("unknown category %q", r.Category)
	}
	if !oneOf(string(r.Modality), string(Text), string(Structured), string(AST), string(Intent)) {
		return fmt.Errorf("unknown modality %q", r.Modality)
	}
	if r.Model.Provider == "" || r.Model.ID == "" || r.Model.Revision == "" || r.Model.Temperature < 0 || r.Model.Temperature > 2 {
		return errors.New("invalid model provenance")
	}
	p := r.Provenance
	if !validDigest(p.DatasetSHA256) || !validDigest(p.TaskSHA256) || !validDigest(p.PromptSHA256) || !validDigest(p.ToolPolicySHA256) || p.HarnessCommit == "" || p.BaseCommit == "" {
		return errors.New("missing/invalid reproducibility provenance")
	}
	if r.TokenBudget == 0 || r.WallTimeMS < 0 {
		return errors.New("invalid budget or wall_time_ms")
	}
	if !oneOf(r.UsageSource, "provider", "estimated", "unavailable") {
		return errors.New("invalid usage_source")
	}
	if r.UsageSource == "unavailable" && len(r.ModelCalls) > 0 {
		return errors.New("usage unavailable but model_calls supplied")
	}
	if r.UsageSource != "unavailable" && len(r.ModelCalls) == 0 {
		return errors.New("usage reported without model calls")
	}
	ids := map[string]bool{}
	for _, c := range r.ModelCalls {
		if c.ID == "" || ids[c.ID] || c.CachedInputTokens > c.InputTokens || c.ReasoningOutputTokens > c.OutputTokens || c.LatencyMS < 0 {
			return errors.New("invalid model call or token subset")
		}
		ids[c.ID] = true
	}
	for _, e := range r.ToolEvents {
		if e.Name == "" || e.LatencyMS < 0 {
			return errors.New("invalid tool event")
		}
	}
	for i, e := range r.EditAttempts {
		if e.Index != i+1 || !validTest(e.PublicTests) || e.LatencyMS < 0 || (e.ErrorLogSHA256 != "" && !validDigest(e.ErrorLogSHA256)) {
			return errors.New("nonconsecutive edit attempt or invalid public result")
		}
	}
	c := r.Coverage
	if c.CandidateCount < 0 || !oneOf(c.Status, "not_applicable", "supported", "unsupported", "unknown") {
		return errors.New("invalid coverage")
	}
	if (r.Modality == Text || r.Modality == Structured) && (c.Status != "not_applicable" || c.CandidateCount != 0 || c.FallbackToText) {
		return errors.New("text modality must use not_applicable coverage")
	}
	if (r.Modality == AST || r.Modality == Intent) && c.Status == "not_applicable" {
		return errors.New("structured modality requires measured coverage")
	}
	if c.FallbackToText && c.FallbackReason == "" {
		return errors.New("fallback requires reason")
	}
	if !c.FallbackToText && c.FallbackReason != "" {
		return errors.New("fallback reason without fallback")
	}
	if !validTest(r.Outcome.PublicTests) || !validTest(r.Outcome.HiddenTests) || !oneOf(r.Outcome.EndReason, "completed", "unsupported", "timeout", "infra_error", "budget_exhausted") {
		return errors.New("invalid outcome")
	}
	if r.Outcome.HiddenTests == "pass" && r.Outcome.EndReason != "completed" {
		return errors.New("hidden pass requires completed run")
	}
	return nil
}

// ReadJSONL rejects unknown fields and duplicate run IDs or repeated experimental
// cells, preventing accidental double-counting. It does not execute user code.
func ReadJSONL(input io.Reader) ([]Run, error) {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), MaxLineBytes)
	var runs []Run
	seenID := map[string]bool{}
	seenCell := map[string]bool{}
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(strings.TrimSpace(string(raw))) == 0 {
			continue
		}
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		var r Run
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("row %d: %w", len(runs)+1, err)
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			return nil, fmt.Errorf("row %d: extra JSON content", len(runs)+1)
		}
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("row %d: %w", len(runs)+1, err)
		}
		key := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s\x00%s", r.TaskID, r.Modality, r.Model.Provider, r.Replicate, r.Model.ID, r.Model.Revision)
		if seenID[r.RunID] || seenCell[key] {
			return nil, fmt.Errorf("row %d: duplicate run ID or experimental cell", len(runs)+1)
		}
		seenID[r.RunID], seenCell[key] = true, true
		runs = append(runs, r)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return runs, nil
}

// Totals uses provider (or explicitly estimated) usage without adding tool
// output a second time. A missing usage is not treated as zero tokens.
func (r Run) Totals() (input, output uint64, available bool) {
	if r.UsageSource == "unavailable" {
		return 0, 0, false
	}
	for _, c := range r.ModelCalls {
		input += c.InputTokens
		output += c.OutputTokens
	}
	return input, output, true
}
