// goai-bench validates and summarizes benchmark JSONL. It does not call LLMs
// or run untrusted tests; those require a separately reviewed harness.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/kbelludoo/goai/internal/benchlog"
)

type Summary struct {
	Modality             benchlog.Modality `json:"modality"`
	Runs                 int               `json:"runs"`
	HiddenPasses         int               `json:"hidden_passes"`
	HiddenEvaluated      int               `json:"hidden_evaluated"`
	Supported            int               `json:"supported"`
	Unsupported          int               `json:"unsupported"`
	UnknownCoverage      int               `json:"unknown_coverage"`
	Fallbacks            int               `json:"fallbacks"`
	Edits                int               `json:"edit_attempts"`
	ProviderUsageRuns    int               `json:"provider_usage_runs"`
	ProviderInputTokens  uint64            `json:"provider_input_tokens"`
	ProviderOutputTokens uint64            `json:"provider_output_tokens"`
	EstimatedUsageRuns   int               `json:"estimated_usage_runs"`
	MissingUsageRuns     int               `json:"missing_usage_runs"`
}

func summarize(runs []benchlog.Run) []Summary {
	groups := map[benchlog.Modality]*Summary{}
	for _, r := range runs {
		s := groups[r.Modality]
		if s == nil {
			s = &Summary{Modality: r.Modality}
			groups[r.Modality] = s
		}
		s.Runs++
		if r.Outcome.HiddenTests != "not_run" {
			s.HiddenEvaluated++
		}
		if r.Outcome.HiddenTests == "pass" {
			s.HiddenPasses++
		}
		switch r.Coverage.Status {
		case "supported":
			s.Supported++
		case "unsupported":
			s.Unsupported++
		case "unknown":
			s.UnknownCoverage++
		}
		if r.Coverage.FallbackToText {
			s.Fallbacks++
		}
		s.Edits += len(r.EditAttempts)
		in, out, ok := r.Totals()
		switch r.UsageSource {
		case "provider":
			if ok {
				s.ProviderUsageRuns++
				s.ProviderInputTokens += in
				s.ProviderOutputTokens += out
			}
		case "estimated":
			s.EstimatedUsageRuns++
		case "unavailable":
			s.MissingUsageRuns++
		}
	}
	out := make([]Summary, 0, len(groups))
	for _, s := range groups {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Modality < out[j].Modality })
	return out
}
func main() {
	file := flag.String("file", "", "JSONL of completed, harness-authored runs")
	flag.Parse()
	if *file == "" {
		fmt.Fprintln(os.Stderr, "usage: goai-bench -file benchmark-runs.jsonl")
		os.Exit(2)
	}
	f, err := os.Open(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	runs, err := benchlog.ReadJSONL(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(runs) == 0 {
		fmt.Fprintln(os.Stderr, "no benchmark runs; refusing to report synthetic success")
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(struct {
		SchemaVersion string    `json:"schema_version"`
		SourceRuns    int       `json:"source_runs"`
		Groups        []Summary `json:"groups"`
	}{benchlog.Version, len(runs), summarize(runs)}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
