package detect

import (
	"fmt"
	"sort"
	"time"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
)

// Report filter modes accepted by Detector.SetReportFilter.
const (
	ReportFilterAll      = "all"
	ReportFilterBlocking = "blocking"
	ReportFilterReported = "reported"
)

// GatingSummary returns the frozen level-gating counters for this scan.
func (d *Detector) GatingSummary() report.GatingSummary {
	return d.gating.summary()
}

// RebuildGating recreates the runtime gating state from the current
// Config.Gating and rule set. It is used when CLI flags override the
// thresholds after the detector was constructed.
func (d *Detector) RebuildGating() {
	d.gating = newGatingStateWithRules(d.Config.Gating, d.Config.Rules)
}

// HasBlockingFindings reports whether any retained finding must fail the
// pipeline. When gating is disabled every retained finding is treated as
// blocking, preserving the historical exit-code behavior.
func (d *Detector) HasBlockingFindings() bool {
	if !d.Config.Gating.Enabled {
		return len(d.findings) > 0
	}
	return d.gating.summary().HasBlocking()
}

// SetReportFilter validates and stores the report output mode. Invalid values
// produce an error listing the accepted range instead of being silently
// ignored.
func (d *Detector) SetReportFilter(filter string) error {
	switch filter {
	case "", ReportFilterAll, ReportFilterBlocking, ReportFilterReported:
		d.ReportFilter = filter
		return nil
	default:
		return fmt.Errorf("invalid report filter %q: valid values are %s, %s, %s",
			filter, ReportFilterAll, ReportFilterBlocking, ReportFilterReported)
	}
}

// filteredFindings applies the configured report mode. "blocking" returns
// findings that fail the pipeline, "reported" returns the non-blocking
// findings (below-threshold plus exempted), and the default returns every
// retained finding.
func (d *Detector) filteredFindings() []report.Finding {
	if d.ReportFilter == "" || d.ReportFilter == ReportFilterAll || !d.Config.Gating.Enabled {
		return d.findings
	}

	filtered := make([]report.Finding, 0, len(d.findings))
	for _, finding := range d.findings {
		switch d.ReportFilter {
		case ReportFilterBlocking:
			if finding.Decision == report.DecisionBlocking {
				filtered = append(filtered, finding)
			}
		case ReportFilterReported:
			if finding.Decision == report.DecisionReported || finding.Decision == report.DecisionExempted {
				filtered = append(filtered, finding)
			}
		}
	}
	return filtered
}

// FilteredFindings returns the findings allowed through the configured report
// mode. When no report filter is set every retained finding is returned.
func (d *Detector) FilteredFindings() []report.Finding {
	return d.filteredFindings()
}

// LogGatingSummary emits the grouped counters and exemption audit to stderr.
func (d *Detector) LogGatingSummary() {
	d.gating.logSummary()
}

// gatingState holds the runtime state for level-based gating. It is created
// once per detector from config.Gating and accumulated during AddFinding.
type gatingState struct {
	config config.GatingConfig

	// knownRules is the rule set of the owning detector, used to audit
	// exemptions targeting non-existent rule IDs.
	knownRules map[string]config.Rule

	now time.Time

	blocking  int
	reported  int
	exempted  int
	baselined int

	// applied maps an exemption pointer to its running usage count.
	applied map[*config.Exemption]int
}

func newGatingState(gating config.GatingConfig) *gatingState {
	if !gating.Enabled {
		return &gatingState{config: gating, now: time.Now()}
	}
	return &gatingState{
		config:  gating,
		now:     time.Now(),
		applied: make(map[*config.Exemption]int),
	}
}

func newGatingStateWithRules(gating config.GatingConfig, rules map[string]config.Rule) *gatingState {
	state := newGatingState(gating)
	state.knownRules = rules
	return state
}

// classify stamps the finding with its rule levels and level-gating decision.
// It must run before baseline/ignore checks so every retained finding carries
// the metadata; callers tally the final outcome once the finding is retained.
func (g *gatingState) classify(finding *report.Finding, rule config.Rule) {
	finding.Severity = rule.Severity.String()
	finding.Confidence = rule.Confidence.String()

	if !g.config.Enabled {
		finding.Decision = report.DecisionUnset
		return
	}

	// An in-scope, non-expired exemption suppresses the blocking decision but
	// never hides the finding. Invalid entries are skipped here and reported
	// separately in the summary.
	if exemption := g.matchExemption(rule.RuleID, finding.File); exemption != nil {
		finding.Decision = report.DecisionExempted
		finding.ExemptionSource = describeExemption(exemption)
		g.applied[exemption]++
		return
	}

	if rule.Severity >= g.config.MinSeverity && rule.Confidence >= g.config.MinConfidence {
		finding.Decision = report.DecisionBlocking
		return
	}

	finding.Decision = report.DecisionReported
}

// matchExemption returns the first valid exemption covering the rule/path
// pair. Expired exemptions and exemptions targeting unknown rules are treated
// as non-matching and surfaced via invalidExemptions instead.
func (g *gatingState) matchExemption(ruleID, path string) *config.Exemption {
	for _, exemption := range g.config.Exemptions {
		if exemption.Expired(g.now) {
			continue
		}
		if exemption.UnknownRule(g.knownRules) {
			continue
		}
		if exemption.Matches(ruleID, path) {
			return exemption
		}
	}
	return nil
}

// tally increments the outcome counter for a retained finding.
func (g *gatingState) tally(decision string) {
	if !g.config.Enabled {
		return
	}
	switch decision {
	case report.DecisionBlocking:
		g.blocking++
	case report.DecisionReported:
		g.reported++
	case report.DecisionExempted:
		g.exempted++
	}
}

func (g *gatingState) tallyBaselined() {
	if g.config.Enabled {
		g.baselined++
	}
}

// undoExemption reverses the exemption usage counted during classification
// when a finding is later suppressed by the baseline.
func (g *gatingState) undoExemption(finding report.Finding) {
	if !g.config.Enabled || finding.Decision != report.DecisionExempted {
		return
	}
	for _, exemption := range g.config.Exemptions {
		if describeExemption(exemption) == finding.ExemptionSource && exemption.Matches(finding.RuleID, finding.File) {
			if g.applied[exemption] > 0 {
				g.applied[exemption]--
				if g.applied[exemption] == 0 {
					delete(g.applied, exemption)
				}
			}
			return
		}
	}
}

// invalidExemptions audits the configured entries for expiry and unknown
// rules. The audit is computed lazily at summary time against the fully
// loaded rule set, so nothing fails silently during a scan.
func (g *gatingState) invalidExemptions() []report.InvalidExemption {
	var invalid []report.InvalidExemption
	for _, exemption := range g.config.Exemptions {
		if exemption.Expired(g.now) {
			invalid = append(invalid, report.InvalidExemption{
				Description: exemption.Description,
				RuleID:      exemption.RuleID,
				Path:        exemption.Path,
				ExpiresAt:   exemption.ExpiresAt,
				Reason:      "exemption has expired",
			})
			continue
		}
		if exemption.UnknownRule(g.knownRules) {
			invalid = append(invalid, report.InvalidExemption{
				Description: exemption.Description,
				RuleID:      exemption.RuleID,
				Path:        exemption.Path,
				ExpiresAt:   exemption.ExpiresAt,
				Reason:      "exemption targets a rule that does not exist",
			})
		}
	}
	return invalid
}

// summary freezes the accumulated counters into a reportable GatingSummary.
func (g *gatingState) summary() report.GatingSummary {
	if !g.config.Enabled {
		return report.GatingSummary{Enabled: false}
	}

	applied := make([]report.ExemptionUse, 0, len(g.applied))
	for exemption, count := range g.applied {
		applied = append(applied, report.ExemptionUse{
			Description: exemption.Description,
			RuleID:      exemption.RuleID,
			Path:        exemption.Path,
			ExpiresAt:   exemption.ExpiresAt,
			Count:       count,
		})
	}
	sort.Slice(applied, func(i, j int) bool {
		if applied[i].RuleID != applied[j].RuleID {
			return applied[i].RuleID < applied[j].RuleID
		}
		return applied[i].Path < applied[j].Path
	})

	return report.GatingSummary{
		Enabled:           true,
		MinSeverity:       g.config.MinSeverity.String(),
		MinConfidence:     g.config.MinConfidence.String(),
		Blocking:          g.blocking,
		Reported:          g.reported,
		Exempted:          g.exempted,
		Baselined:         g.baselined,
		AppliedExemptions: applied,
		InvalidExemptions: g.invalidExemptions(),
	}
}

func describeExemption(exemption *config.Exemption) string {
	if exemption.Description != "" {
		return fmt.Sprintf("exemption: %s", exemption.Description)
	}
	if exemption.RuleID != "" && exemption.Path != "" {
		return fmt.Sprintf("exemption: rule %s on path %s", exemption.RuleID, exemption.Path)
	}
	if exemption.RuleID != "" {
		return fmt.Sprintf("exemption: rule %s", exemption.RuleID)
	}
	return fmt.Sprintf("exemption: path %s", exemption.Path)
}

// logSummary writes the grouped counters and exemption audit to stderr so
// callers can interpret the exit code even without a report file.
func (g *gatingState) logSummary() {
	if !g.config.Enabled {
		return
	}
	summary := g.summary()
	logging.Info().
		Str("minSeverity", summary.MinSeverity).
		Str("minConfidence", summary.MinConfidence).
		Msg("level gating enabled")
	logging.Info().
		Int("blocking", summary.Blocking).
		Int("reported", summary.Reported).
		Int("exempted", summary.Exempted).
		Int("baselined", summary.Baselined).
		Msg("gating summary")

	for _, use := range summary.AppliedExemptions {
		logging.Info().
			Str("rule-id", use.RuleID).
			Str("path", use.Path).
			Int("findings", use.Count).
			Msgf("exemption applied: %s", use.Description)
	}
	for _, invalid := range summary.InvalidExemptions {
		logging.Warn().
			Str("rule-id", invalid.RuleID).
			Str("path", invalid.Path).
			Msgf("exemption not applied (%s): %s", invalid.Reason, invalid.Description)
	}

	if summary.Blocking == 0 &&
		summary.Reported == 0 &&
		summary.Exempted == 0 &&
		summary.Baselined == 0 {
		logging.Info().Msg("no findings after level gating")
	}
}
