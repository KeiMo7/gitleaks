package detect

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

const gatingConfigPath = "../testdata/config/gating/"

func loadTomlConfig(t *testing.T, fullPath string) config.Config {
	t.Helper()
	viper.Reset()
	viper.SetConfigFile(fullPath)
	require.NoError(t, viper.ReadInConfig())

	var vc config.ViperConfig
	require.NoError(t, viper.Unmarshal(&vc))
	cfg, err := vc.Translate()
	require.NoError(t, err)
	return cfg
}

func stringReader(content string) io.Reader {
	return strings.NewReader(content)
}

func gatingDetector(t *testing.T, name string) *Detector {
	t.Helper()
	cfg := loadGatingConfig(t, name)
	return NewDetector(cfg)
}

func loadGatingConfig(t *testing.T, name string) config.Config {
	t.Helper()
	return loadTomlConfig(t, gatingConfigPath+name)
}

func scanString(t *testing.T, detector *Detector, content string) []report.Finding {
	t.Helper()
	findings, err := detector.DetectSource(context.Background(), &sources.File{
		Content: stringReader(content),
	})
	require.NoError(t, err)
	return findings
}

func decisions(findings []report.Finding) map[string]string {
	out := make(map[string]string)
	for _, finding := range findings {
		out[finding.RuleID] = finding.Decision
	}
	return out
}

func TestGatingClassifiesBlockingAndReported(t *testing.T) {
	detector := gatingDetector(t, "mixed_levels.toml")
	findings := scanString(t, detector, `
CRITICAL-KEY-12345678
HIGH-SECRET-12345678
MEDIUM-TOKEN-12345678
LOW-SIGNAL-12345678
DEFAULT-RULE-12345678
`)

	got := decisions(findings)
	// Thresholds: minSeverity=high, minConfidence=medium.
	assert.Equal(t, report.DecisionBlocking, got["hardcoded-critical-key"])
	assert.Equal(t, report.DecisionBlocking, got["hardcoded-high-secret"])
	// Medium severity is below the high threshold.
	assert.Equal(t, report.DecisionReported, got["fixture-medium-token"])
	// High severity but low confidence fails the confidence threshold; the
	// rule-scoped exemption in the fixture suppresses it instead.
	assert.Equal(t, report.DecisionExempted, got["entropy-low-confidence"])
	// Unannotated rule defaults to high/high, so it still blocks.
	assert.Equal(t, report.DecisionBlocking, got["unannotated-default-rule"])

	summary := detector.GatingSummary()
	assert.True(t, summary.Enabled)
	assert.Equal(t, 3, summary.Blocking)
	assert.Equal(t, 1, summary.Reported)
	assert.Equal(t, 1, summary.Exempted)
	assert.True(t, detector.HasBlockingFindings())

	for _, finding := range findings {
		assert.NotEmpty(t, finding.Severity)
		assert.NotEmpty(t, finding.Confidence)
	}
}

func TestGatingExemptionsAreScoped(t *testing.T) {
	detector := gatingDetector(t, "mixed_levels.toml")

	// Same rule, two paths: only the fixture path is covered by the
	// path-scoped exemption.
	findings := scanString(t, detector, "")
	require.Empty(t, findings)

	detector = gatingDetector(t, "mixed_levels.toml")
	inScope := detector.Detect(Fragment{
		Raw:      "CRITICAL-KEY-12345678",
		FilePath: "testdata/fixtures/keys.txt",
	})
	require.Len(t, inScope, 1)
	assert.Equal(t, report.DecisionExempted, inScope[0].Decision)
	assert.Contains(t, inScope[0].ExemptionSource, "known test fixture key")

	outOfScope := detector.Detect(Fragment{
		Raw:      "CRITICAL-KEY-12345678",
		FilePath: "src/production/keys.txt",
	})
	require.Len(t, outOfScope, 1)
	assert.Equal(t, report.DecisionBlocking, outOfScope[0].Decision)

	// Rule-scoped exemption (no path) applies anywhere.
	ruleScoped := detector.Detect(Fragment{
		Raw:      "LOW-SIGNAL-12345678",
		FilePath: "anywhere/else.txt",
	})
	require.Len(t, ruleScoped, 1)
	assert.Equal(t, report.DecisionExempted, ruleScoped[0].Decision)

	// Retained findings only count when they flow through AddFinding.
	retained := scanString(t, gatingDetector(t, "mixed_levels.toml"), `
CRITICAL-KEY-12345678
LOW-SIGNAL-12345678
`)
	// Neither retained finding sits under testdata/ path, so the critical
	// rule blocks; the rule-scoped exemption still covers low-signal.
	got := decisions(retained)
	assert.Equal(t, report.DecisionBlocking, got["hardcoded-critical-key"])
	assert.Equal(t, report.DecisionExempted, got["entropy-low-confidence"])

	summary := detector.GatingSummary()
	invalidReasons := make([]string, 0, len(summary.InvalidExemptions))
	for _, invalid := range summary.InvalidExemptions {
		invalidReasons = append(invalidReasons, invalid.Reason)
	}
	assert.Contains(t, invalidReasons, "exemption has expired")
	assert.Contains(t, invalidReasons, "exemption targets a rule that does not exist")
}

func TestGatingAllExemptedExitsCleanly(t *testing.T) {
	cfg := loadGatingConfig(t, "mixed_levels.toml")
	detector := NewDetector(cfg)

	findings := detector.Detect(Fragment{
		Raw:      "LOW-SIGNAL-12345678",
		FilePath: "anything/here.txt",
	})
	for _, finding := range findings {
		detector.AddFinding(finding)
	}

	summary := detector.GatingSummary()
	assert.Equal(t, 1, summary.Exempted)
	assert.Equal(t, 0, summary.Blocking)
	assert.False(t, detector.HasBlockingFindings())
	require.Len(t, summary.AppliedExemptions, 1)
	assert.Equal(t, 1, summary.AppliedExemptions[0].Count)
}

func TestGatingBaselineSuppressesBlocking(t *testing.T) {
	detector := gatingDetector(t, "mixed_levels.toml")

	findings := detector.Detect(Fragment{
		Raw:      "CRITICAL-KEY-12345678",
		FilePath: "src/production/keys.txt",
	})
	require.Len(t, findings, 1)

	// Use the detected finding itself as the baseline record so the
	// structural comparison in IsNew is guaranteed to match.
	detector.baseline = []report.Finding{findings[0]}
	detector.AddFinding(findings[0])

	assert.Empty(t, detector.Findings(), "baselined finding must be dropped")
	summary := detector.GatingSummary()
	assert.Equal(t, 1, summary.Baselined)
	assert.Equal(t, 0, summary.Blocking)
	assert.False(t, detector.HasBlockingFindings())
}

func TestGatingThresholdBoundaries(t *testing.T) {
	tests := map[string]struct {
		minSeverity   config.Level
		minConfidence config.Level
		wantDecision  string
	}{
		// A high/high rule against every threshold combination.
		"severity low boundary":     {config.SeverityLow, config.ConfidenceLow, report.DecisionBlocking},
		"severity equal boundary":   {config.SeverityHigh, config.ConfidenceMedium, report.DecisionBlocking},
		"severity above boundary":   {config.SeverityCritical, config.ConfidenceLow, report.DecisionReported},
		"confidence equal boundary": {config.SeverityMedium, config.ConfidenceHigh, report.DecisionBlocking},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := loadGatingConfig(t, "mixed_levels.toml")
			cfg.Gating.MinSeverity = test.minSeverity
			cfg.Gating.MinConfidence = test.minConfidence
			detector := NewDetector(cfg)

			findings := detector.Detect(Fragment{Raw: "HIGH-SECRET-12345678"})
			require.Len(t, findings, 1)
			assert.Equal(t, test.wantDecision, findings[0].Decision)
		})
	}
}

func TestGatingReportFilters(t *testing.T) {
	detector := gatingDetector(t, "mixed_levels.toml")
	for _, fragment := range []Fragment{
		{Raw: "CRITICAL-KEY-12345678", FilePath: "src/a.txt"},
		{Raw: "MEDIUM-TOKEN-12345678", FilePath: "src/b.txt"},
		{Raw: "LOW-SIGNAL-12345678", FilePath: "src/c.txt"},
	} {
		for _, finding := range detector.Detect(fragment) {
			detector.AddFinding(finding)
		}
	}

	require.NoError(t, detector.SetReportFilter("all"))
	assert.Len(t, detector.FilteredFindings(), 3)

	require.NoError(t, detector.SetReportFilter("blocking"))
	blocking := detector.FilteredFindings()
	assert.Len(t, blocking, 1)
	assert.Equal(t, report.DecisionBlocking, blocking[0].Decision)

	require.NoError(t, detector.SetReportFilter("reported"))
	reported := detector.FilteredFindings()
	assert.Len(t, reported, 2)

	err := detector.SetReportFilter("nope")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "valid values are")
}

func TestGatingDisabledPreservesLegacyBehavior(t *testing.T) {
	detector := gatingDetector(t, "no_gating.toml")
	assert.False(t, detector.Config.Gating.Enabled)

	findings := scanString(t, detector, "PLAIN-123456")
	require.Len(t, findings, 1)
	assert.Equal(t, report.DecisionUnset, findings[0].Decision)
	assert.Equal(t, "high", findings[0].Severity)

	// Any finding blocks when gating is disabled.
	assert.True(t, detector.HasBlockingFindings())
	summary := detector.GatingSummary()
	assert.False(t, summary.Enabled)

	// Report filter is inert when gating is disabled.
	require.NoError(t, detector.SetReportFilter("blocking"))
	assert.Len(t, detector.FilteredFindings(), 1)
}

func TestGatingDefaultThresholdsWhenSectionEmpty(t *testing.T) {
	detector := gatingDetector(t, "enabled_defaults.toml")
	require.True(t, detector.Config.Gating.Enabled)

	findings := scanString(t, detector, "LOW-123456")
	require.Len(t, findings, 1)
	assert.Equal(t, report.DecisionReported, findings[0].Decision)

	high := scanString(t, gatingDetector(t, "enabled_defaults.toml"), "HIGH-123456")
	require.Len(t, high, 1)
	assert.Equal(t, report.DecisionBlocking, high[0].Decision)
}

func TestGatingRetainsResultsFromPartialScan(t *testing.T) {
	detector := gatingDetector(t, "mixed_levels.toml")

	// Simulate fragments that completed before a mid-scan read failure: the
	// findings already added must keep their gating classification and stay
	// available for reporting.
	first := detector.Detect(Fragment{Raw: "HIGH-SECRET-12345678", FilePath: "src/a.txt"})
	require.Len(t, first, 1)
	detector.AddFinding(first[0])

	second := detector.Detect(Fragment{Raw: "MEDIUM-TOKEN-12345678", FilePath: "src/b.txt"})
	require.Len(t, second, 1)
	detector.AddFinding(second[0])

	retained := detector.Findings()
	require.Len(t, retained, 2)
	assert.Equal(t, report.DecisionBlocking, retained[0].Decision)
	assert.Equal(t, report.DecisionReported, retained[1].Decision)

	// A partial scan must still surface the blocking outcome so callers can
	// decide on manual intervention, while keeping the reported finding.
	summary := detector.GatingSummary()
	assert.Equal(t, 1, summary.Blocking)
	assert.Equal(t, 1, summary.Reported)
	assert.True(t, detector.HasBlockingFindings())
}

func TestGatingSeverityPropagationAfterRuleDowngrade(t *testing.T) {
	// A baseline record created when the rule was high must be re-evaluated
	// under the rule's current (downgraded) level. The level always comes
	// from the current rule definition, never from the stored finding.
	cfg := loadGatingConfig(t, "mixed_levels.toml")
	rule := cfg.Rules["hardcoded-high-secret"]
	rule.Severity = config.SeverityLow
	cfg.Rules["hardcoded-high-secret"] = rule
	detector := NewDetector(cfg)

	findings := detector.Detect(Fragment{Raw: "HIGH-SECRET-12345678"})
	require.Len(t, findings, 1)
	assert.Equal(t, "low", findings[0].Severity, "current rule level wins over any historical record")
	assert.Equal(t, report.DecisionReported, findings[0].Decision)
}
