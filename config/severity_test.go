package config

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func nowish() time.Time {
	return time.Date(2026, time.November, 19, 0, 0, 0, 0, time.UTC)
}

func mustRegex(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}

func loadConfig(t *testing.T, name string) Config {
	t.Helper()
	extendDepth = 0
	viper.Reset()
	viper.AddConfigPath(configPath)
	viper.SetConfigName(name)
	viper.SetConfigType("toml")
	require.NoError(t, viper.ReadInConfig())

	var vc ViperConfig
	require.NoError(t, viper.Unmarshal(&vc))
	cfg, err := vc.Translate()
	require.NoError(t, err)
	t.Cleanup(func() {
		extendDepth = 0
		viper.Reset()
	})
	return cfg
}

func loadConfigExpectError(t *testing.T, name string) error {
	t.Helper()
	extendDepth = 0
	viper.Reset()
	viper.AddConfigPath(configPath)
	viper.SetConfigName(name)
	viper.SetConfigType("toml")
	require.NoError(t, viper.ReadInConfig())

	var vc ViperConfig
	require.NoError(t, viper.Unmarshal(&vc))
	_, err := vc.Translate()
	require.Error(t, err)
	t.Cleanup(func() {
		extendDepth = 0
		viper.Reset()
	})
	return err
}

func TestParseLevel(t *testing.T) {
	t.Parallel()
	tests := map[string]Level{
		"LOW":      LevelLow,
		"medium":   LevelMedium,
		" High ":   LevelHigh,
		"critical": LevelCritical,
	}
	for input, expected := range tests {
		got, err := ParseLevel(input)
		require.NoError(t, err)
		assert.Equal(t, expected, got)
	}

	_, err := ParseLevel("urgent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "valid values are")
}

func TestRuleLevelDefaultsAreConservative(t *testing.T) {
	cfg := loadConfig(t, "gating/no_gating")

	rule := cfg.Rules["plain-rule"]
	assert.Equal(t, SeverityHigh, rule.Severity, "unannotated severity must default to high")
	assert.Equal(t, ConfidenceHigh, rule.Confidence, "unannotated confidence must default to high")
	assert.False(t, cfg.Gating.Enabled, "gating must stay disabled without a [gating] section")
}

func TestExplicitRuleLevelsAreParsed(t *testing.T) {
	cfg := loadConfig(t, "gating/mixed_levels")

	assert.Equal(t, SeverityCritical, cfg.Rules["hardcoded-critical-key"].Severity)
	assert.Equal(t, ConfidenceHigh, cfg.Rules["hardcoded-critical-key"].Confidence)
	assert.Equal(t, SeverityMedium, cfg.Rules["fixture-medium-token"].Severity)
	assert.Equal(t, ConfidenceLow, cfg.Rules["entropy-low-confidence"].Confidence)

	// Unannotated rule keeps the conservative default.
	assert.Equal(t, SeverityHigh, cfg.Rules["unannotated-default-rule"].Severity)
	assert.Equal(t, ConfidenceHigh, cfg.Rules["unannotated-default-rule"].Confidence)
}

func TestUnknownRuleLevelFallsBackConservatively(t *testing.T) {
	cfg := loadConfig(t, "gating/unknown_rule_level")

	rule := cfg.Rules["typo-level-rule"]
	assert.Equal(t, SeverityHigh, rule.Severity, "unknown annotation must fall back to high")
	assert.Equal(t, ConfidenceHigh, rule.Confidence)
}

func TestGatingThresholdsAndExemptionsLoad(t *testing.T) {
	cfg := loadConfig(t, "gating/mixed_levels")

	require.True(t, cfg.Gating.Enabled)
	assert.Equal(t, SeverityHigh, cfg.Gating.MinSeverity)
	assert.Equal(t, ConfidenceMedium, cfg.Gating.MinConfidence)
	require.Len(t, cfg.Gating.Exemptions, 4)

	// Scoped exemptions must match only within their declared scope.
	pathScoped := cfg.Gating.Exemptions[0]
	assert.True(t, pathScoped.Matches("hardcoded-critical-key", "testdata/keys/prod.txt"))
	assert.False(t, pathScoped.Matches("hardcoded-critical-key", "src/keys/prod.txt"))
	assert.False(t, pathScoped.Matches("hardcoded-high-secret", "testdata/keys/prod.txt"))

	ruleScoped := cfg.Gating.Exemptions[1]
	assert.True(t, ruleScoped.Matches("entropy-low-confidence", "anywhere/file.txt"))
	assert.False(t, ruleScoped.Matches("hardcoded-high-secret", "anywhere/file.txt"))
	assert.False(t, ruleScoped.Expired(nowish()))

	expired := cfg.Gating.Exemptions[2]
	assert.True(t, expired.Expired(nowish()))

	unknown := cfg.Gating.Exemptions[3]
	assert.True(t, unknown.UnknownRule(cfg.Rules))
}

func TestGatingEnabledWithoutThresholdsUsesDefaults(t *testing.T) {
	cfg := loadConfig(t, "gating/enabled_defaults")

	require.True(t, cfg.Gating.Enabled)
	assert.Equal(t, DefaultMinSeverity, cfg.Gating.MinSeverity)
	assert.Equal(t, DefaultMinConfidence, cfg.Gating.MinConfidence)
}

func TestInvalidGatingConfigFailsAtLoad(t *testing.T) {
	err := loadConfigExpectError(t, "invalid/gating_bad_severity")
	assert.Contains(t, err.Error(), "invalid [gating] minSeverity")
	assert.Contains(t, err.Error(), "critical")

	err = loadConfigExpectError(t, "invalid/gating_bad_confidence")
	assert.Contains(t, err.Error(), "invalid [gating] minConfidence")

	err = loadConfigExpectError(t, "invalid/gating_exemption_no_scope")
	assert.Contains(t, err.Error(), "must scope at least one of ruleID or path")
}

func TestExemptionValidateRejectsUnknownRuleLevel(t *testing.T) {
	rule := Rule{RuleID: "x", Regex: mustRegex("x"), Severity: LevelUnknown, Confidence: LevelHigh}
	err := rule.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown severity annotation")
}

func TestRuleLevelsPropagateThroughExtend(t *testing.T) {
	cfg := loadConfig(t, "gating/extend_levels")

	// Explicit child annotation overrides the base level.
	downgraded := cfg.Rules["leveled-rule"]
	assert.Equal(t, SeverityLow, downgraded.Severity)
	assert.Equal(t, ConfidenceLow, downgraded.Confidence)

	// Unannotated child override inherits the base level instead of
	// resetting to the high/high conservative default.
	inherited := cfg.Rules["inherited-rule"]
	assert.Equal(t, SeverityMedium, inherited.Severity)
	assert.Equal(t, ConfidenceMedium, inherited.Confidence)
}
