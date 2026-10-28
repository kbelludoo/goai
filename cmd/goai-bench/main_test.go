package main

import (
	"github.com/kbelludoo/goai/internal/benchlog"
	"testing"
)

func TestSummaryDoesNotTreatUnavailableAsZero(t *testing.T) {
	r := benchlog.Run{Modality: benchlog.Intent, UsageSource: "unavailable", Coverage: benchlog.Coverage{Status: "unsupported", FallbackToText: true}, Outcome: benchlog.Outcome{HiddenTests: "not_run"}, EditAttempts: []benchlog.EditAttempt{{}}}
	s := summarize([]benchlog.Run{r})
	if len(s) != 1 || s[0].Runs != 1 || s[0].MissingUsageRuns != 1 || s[0].HiddenEvaluated != 0 || s[0].Unsupported != 1 || s[0].Fallbacks != 1 || s[0].ProviderInputTokens != 0 {
		t.Fatalf("bad summary: %+v", s)
	}
}
