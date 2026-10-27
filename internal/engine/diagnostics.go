package engine

// Diagnostic is the only failure channel. Codes are stable; Message is for
// humans, Hint says what a caller can do next, and Retryable distinguishes
// "your patch was wrong, fix it" from "the environment says no".
type Diagnostic struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Hint      string `json:"hint,omitempty"`
	File      string `json:"file,omitempty"`
	Line      int    `json:"line,omitempty"`
	Column    int    `json:"column,omitempty"`
	Retryable bool   `json:"retryable,omitempty"`
	// Candidates is populated when the target was not unique, so a caller can
	// disambiguate without guessing or re-reading the whole file.
	Candidates []Site `json:"candidates,omitempty"`
}

// Site is one editable assignment: the exact information needed to build a
// patch, plus a RetryTarget that can be sent back verbatim.
type Site struct {
	Symbol        string `json:"symbol"`
	AssignmentLHS string `json:"assignment_lhs"`
	Operator      string `json:"operator"`
	File          string `json:"file,omitempty"`
	Line          int    `json:"line"`
	Column        int    `json:"column"`
	Occurrence    int    `json:"occurrence"`
	RetryTarget   Target `json:"retry_target"`
}

// NextAction tells a caller what the tool deliberately did not do. It exists so
// agents do not have to infer workflow from prose: validation stops at
// type-checking, so tests are always an explicit next step.
type NextAction struct {
	Kind        string         `json:"kind"`
	Description string         `json:"description"`
	Patch       map[string]any `json:"patch,omitempty"`
}
