package report

// Level-gating decisions recorded on each Finding when gating is enabled.
const (
	// DecisionUnset is used when level gating is disabled. Findings with
	// this decision keep the historical "any finding blocks" semantics.
	DecisionUnset = "unset"

	// DecisionBlocking means the finding's severity and confidence both meet
	// the configured thresholds and no exemption applies. These findings
	// cause the non-zero exit code.
	DecisionBlocking = "blocking"

	// DecisionReported means the finding is below at least one threshold. It
	// is reported but does not fail the pipeline.
	DecisionReported = "reported"

	// DecisionExempted means a scoped, non-expired exemption suppressed the
	// blocking decision. The finding remains visible and is counted
	// separately with its exemption source.
	DecisionExempted = "exempted"
)

// GatingSummary is the end-of-scan tally of level-gating outcomes. It is
// always populated when gating is enabled, including partial scans, and is
// logged to stderr so the exit code can be interpreted without a report file.
type GatingSummary struct {
	Enabled       bool `json:"enabled"`
	MinSeverity   string
	MinConfidence string

	Blocking  int
	Reported  int
	Exempted  int
	Baselined int

	// AppliedExemptions lists the distinct exemption sources that actually
	// suppressed at least one finding.
	AppliedExemptions []ExemptionUse `json:",omitempty"`

	// InvalidExemptions lists expired entries and entries pointing at rules
	// that do not exist. They never suppress findings and are surfaced here
	// so they cannot silently take effect.
	InvalidExemptions []InvalidExemption `json:",omitempty"`
}

// ExemptionUse records that an exemption was applied, with the number of
// findings it suppressed.
type ExemptionUse struct {
	Description string
	RuleID      string
	Path        string
	ExpiresAt   string
	Count       int
}

// InvalidExemption describes an exemption entry that could not take effect.
type InvalidExemption struct {
	Description string
	RuleID      string
	Path        string
	ExpiresAt   string
	Reason      string
}

// HasBlocking reports whether any finding requires pipeline failure.
func (s GatingSummary) HasBlocking() bool {
	return s.Enabled && s.Blocking > 0
}
