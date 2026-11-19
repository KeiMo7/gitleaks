package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfidenceIsDisabled(t *testing.T) {
	cfg := DefaultConfidenceConfig()
	assert.False(t, cfg.Enabled, "built-in default must not enable the feature implicitly")
	assert.Equal(t, ConfidenceSchemaVersion, cfg.SchemaVersion)
	assert.NoError(t, cfg.Validate())
}

func TestConfidenceTranslateInheritsDefaults(t *testing.T) {
	vc := ViperConfidence{Enabled: true, SchemaVersion: "1"}
	cfg, err := vc.Translate()
	require.NoError(t, err)
	assert.True(t, cfg.Enabled)
	assert.InDelta(t, DefaultConfidenceConfig().Decision.ReportThreshold, cfg.Decision.ReportThreshold, 1e-9)
	assert.InDelta(t, DefaultConfidenceConfig().Scoring.KnownPrefix, cfg.Scoring.KnownPrefix, 1e-9)
}

func TestConfidenceTranslateOverrides(t *testing.T) {
	vc := ViperConfidence{
		Enabled:       true,
		SchemaVersion: "1",
		Decision:      &ViperConfidenceDecision{ReportThreshold: 0.6, HighConfidenceThreshold: 0.9},
		Prefixes:      []string{"custom_"},
	}
	cfg, err := vc.Translate()
	require.NoError(t, err)
	assert.InDelta(t, 0.6, cfg.Decision.ReportThreshold, 1e-9)
	assert.InDelta(t, 0.9, cfg.Decision.HighConfidenceThreshold, 1e-9)
	assert.Equal(t, []string{"custom_"}, cfg.Prefixes)
}

func TestConfidenceValidateRejectsBadThresholds(t *testing.T) {
	cases := map[string]func(c *ConfidenceConfig){
		"report threshold out of range":   func(c *ConfidenceConfig) { c.Decision.ReportThreshold = 1.5 },
		"high below report threshold":     func(c *ConfidenceConfig) { c.Decision.HighConfidenceThreshold = 0.2 },
		"non-positive entropy threshold":  func(c *ConfidenceConfig) { c.Entropy.HighThreshold = 0 },
		"min hits below one":              func(c *ConfidenceConfig) { c.Resource.MinHits = 0 },
		"cluster similarity out of range": func(c *ConfidenceConfig) { c.Cluster.SimilarityThreshold = 2 },
		"negative weight":                 func(c *ConfidenceConfig) { c.Scoring.KnownPrefix = -1 },
		"unsupported schema version":      func(c *ConfidenceConfig) { c.SchemaVersion = "2" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := DefaultConfidenceConfig()
			c.Enabled = true
			mutate(&c)
			assert.Error(t, c.Validate())
		})
	}
}

func TestLoadConfidenceConfigMissingIsDegradedNotFatal(t *testing.T) {
	cfg, degraded := LoadConfidenceConfig(filepath.Join(t.TempDir(), "nope.toml"))
	require.NotNil(t, degraded)
	assert.False(t, degraded.HardReject)
	assert.True(t, cfg.Enabled)
}

func TestLoadConfidenceConfigMalformedIsDegraded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.toml")
	require.NoError(t, os.WriteFile(path, []byte("enabled = true\nbroken = ["), 0o600))
	cfg, degraded := LoadConfidenceConfig(path)
	require.NotNil(t, degraded)
	assert.False(t, degraded.HardReject)
	assert.True(t, cfg.Enabled)
}

func TestLoadConfidenceConfigSchemaMismatchHardRejects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "schema.toml")
	require.NoError(t, os.WriteFile(path, []byte(`enabled = true
schema_version = "42"
`), 0o600))
	_, degraded := LoadConfidenceConfig(path)
	require.NotNil(t, degraded)
	assert.True(t, degraded.HardReject)
}

func TestLoadConfidenceConfigEmptyPathReturnsDefaults(t *testing.T) {
	cfg, degraded := LoadConfidenceConfig("")
	require.Nil(t, degraded)
	assert.False(t, cfg.Enabled)
}
