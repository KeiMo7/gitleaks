package detect

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// loadConfidenceTestConfig parses testdata/config/confidence_joint.toml into
// a runtime config with the joint pipeline enabled.
func loadConfidenceTestConfig(t *testing.T) config.Config {
	t.Helper()
	viper.Reset()
	viper.AddConfigPath(configPath)
	viper.SetConfigName("confidence_joint")
	viper.SetConfigType("toml")
	require.NoError(t, viper.ReadInConfig())

	var vc config.ViperConfig
	require.NoError(t, viper.Unmarshal(&vc))
	cfg, err := vc.Translate()
	require.NoError(t, err)
	cfg.Path = filepath.Join(configPath, "confidence_joint.toml")
	require.NotNil(t, cfg.Confidence, "joint confidence must be enabled by the fixture")
	return cfg
}

// newJointDetector builds a detector whose marks file lives in a temp dir so
// tests never touch the working copy's .gitleaks-marks.json.
func newJointDetector(t *testing.T) (*Detector, string) {
	t.Helper()
	cfg := loadConfidenceTestConfig(t)
	marksDir := t.TempDir()
	cfg.Confidence.Marks.Path = filepath.Join(marksDir, "marks.json")

	d := NewDetector(cfg)
	require.NoError(t, d.EnableConfidence())
	return d, marksDir
}

// newJointDetectorAt reuses an existing (validated) config but points the
// marks store at a specific path, simulating a fresh scan process.
func newJointDetectorAt(t *testing.T, cfg config.Config, marksPath string) (*Detector, string) {
	t.Helper()
	cfg.Confidence.Marks.Path = marksPath
	d := NewDetector(cfg)
	require.NoError(t, d.EnableConfidence())
	return d, filepath.Dir(marksPath)
}

// TestHighEntropyResourceStringDoesNotAlarm is acceptance case #2: a high
// entropy build/resource string must not produce a finding on its own.
func TestHighEntropyResourceStringDoesNotAlarm(t *testing.T) {
	d, _ := newJointDetector(t)

	// A high-entropy (>=4.0) random-looking blob carrying two corroborating
	// resource indicators: a resource content pattern and a build-output path.
	fragment := Fragment{
		Raw:      `app_secret = "Xq8vZm3kPw2nRt6yHb9cLd4fGj7sNk5p01"`,
		FilePath: "dist/app.bundle.min.js",
	}
	findings := d.Detect(fragment)

	assert.Empty(t, findings, "a high-entropy build/resource string must not alarm on its own")
}

// TestHighEntropyResourceStringWouldAlarmWithoutJoint proves the suppression
// is caused by the joint decision rather than by the regex failing: the same
// input under the legacy pipeline DOES match and passes its entropy gate.
func TestHighEntropyResourceStringWouldAlarmWithoutJoint(t *testing.T) {
	cfg := loadConfidenceTestConfig(t)
	cfg.Confidence = nil // disable joint decision -> legacy behavior
	d := NewDetector(cfg)

	fragment := Fragment{
		Raw:      `app_secret = "Xq8vZm3kPw2nRt6yHb9cLd4fGj7sNk5p01"`,
		FilePath: "dist/app.bundle.min.js",
	}
	findings := d.Detect(fragment)
	require.Len(t, findings, 1, "legacy pipeline still matches the blob via the generic rule")
	assert.Empty(t, findings[0].ConfidenceReasons, "legacy findings carry no confidence metadata")
}

// TestShortPrefixedCredentialHighConfidence is acceptance case #3: a short
// credential with a known prefix is detected and scores high confidence.
func TestShortPrefixedCredentialHighConfidence(t *testing.T) {
	d, _ := newJointDetector(t)

	// Only 12 chars after the prefix; a legacy entropy gate at 3.5 rejects it.
	fragment := Fragment{
		Raw:      `token = "ghp_K2mQx7"`,
		FilePath: "config/app.yaml",
	}
	findings := d.Detect(fragment)

	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, "short-prefixed-token", f.RuleID)
	assert.Equal(t, "high", f.ConfidenceLevel, "a known-prefix credential must be high confidence")
	assert.Contains(t, f.ConfidenceReasons, "prefix:known")
	assert.Contains(t, f.ConfidenceReasons, "rule:named")
	assert.GreaterOrEqual(t, f.ConfidenceScore, float32(0.75))
}

// TestShortPrefixedCredentialWouldBeDroppedByLegacyGate documents the exact
// false negative the feature fixes.
func TestShortPrefixedCredentialWouldBeDroppedByLegacyGate(t *testing.T) {
	cfg := loadConfidenceTestConfig(t)
	cfg.Confidence = nil
	d := NewDetector(cfg)

	for _, raw := range []string{`token = "ghp_K2mQx7"`, `token = "ghp_aabb"`} {
		findings := d.Detect(Fragment{
			Raw:      raw,
			FilePath: "config/app.yaml",
		})
		assert.Empty(t, findings, "legacy hard entropy gate drops %q", raw)
	}
}

// TestVeryShortPrefixedCredentialHighConfidence is the strongest form of
// acceptance case #3: an 8-char prefixed credential whose entropy is far below
// any realistic gate, but whose known prefix makes it high confidence.
func TestVeryShortPrefixedCredentialHighConfidence(t *testing.T) {
	d, _ := newJointDetector(t)

	findings := d.Detect(Fragment{
		Raw:      `token = "ghp_aabb"`,
		FilePath: "config/app.yaml",
	})
	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, "short-prefixed-token", f.RuleID)
	assert.Equal(t, "high", f.ConfidenceLevel)
	assert.Contains(t, f.ConfidenceReasons, "prefix:known")
	assert.Less(t, f.Entropy, float32(3.5), "the credential genuinely is low entropy")
}

// TestMultipleSimilarHitsMergeToOneFileAlert is coverage #3: several similar
// hits in one file collapse into a single finding, keeping the most confident.
func TestMultipleSimilarHitsMergeToOneFileAlert(t *testing.T) {
	d, _ := newJointDetector(t)

	fragment := Fragment{
		FilePath: "config/settings.yaml",
		Raw: `secret = "Xq8vZm3kPw2nRt6yHb9cLd4fGj7sNk5p01"
secret = "Xq8vZm3kPw2nRt6yHb9cLd4fGj7sNk5p02"
secret = "Xq8vZm3kPw2nRt6yHb9cLd4fGj7sNk5p03"
`,
	}
	findings := d.Detect(fragment)

	require.Len(t, findings, 1, "similar hits in one file must merge into one alert")
	assert.Contains(t, findings[0].ConfidenceReasons, "cluster:merged-duplicate")
}

// TestRuleEntropyConflictResolvedByConfidence is coverage #4: rule/entropy
// conflicts are resolved by confidence rather than a logical OR.
func TestRuleEntropyConflictResolvedByConfidence(t *testing.T) {
	d, _ := newJointDetector(t)

	// Generic rule on a low-entropy, non-prefixed string: below threshold.
	low := d.Detect(Fragment{
		Raw:      `password = "abcdefghij"`,
		FilePath: "config/plain.txt",
	})
	assert.Empty(t, low, "weak generic match below report threshold must be vetoed")

	// Named prefix match with weak entropy still wins on confidence.
	high := d.Detect(Fragment{
		Raw:      `token = "tok_Zx1Yw2Vu"`,
		FilePath: "config/plain.txt",
	})
	require.Len(t, high, 1)
	assert.Equal(t, "high", high[0].ConfidenceLevel)
}

// TestFindingsSortedByConfidence is coverage #7: joint findings come back in
// descending confidence order with deterministic tie breaks.
func TestFindingsSortedByConfidence(t *testing.T) {
	d, _ := newJointDetector(t)

	fragment := Fragment{
		FilePath: "mixed/config.txt",
		Raw: `token = "ghp_K2mQx7"
secret = "Xq8vZm3kPw2nRt6yHb9cLd4fGj7sNk5p01"
`,
	}
	findings := d.Detect(fragment)
	require.GreaterOrEqual(t, len(findings), 1)
	for i := 1; i < len(findings); i++ {
		assert.GreaterOrEqual(t, findings[i-1].ConfidenceScore, findings[i].ConfidenceScore,
			"findings must be sorted by confidence descending")
	}
}

// findingSnapshot is a compact, comparable view of a finding.
type findingSnapshot struct {
	rule    string
	line    int
	score   float32
	level   string
	reasons string
}

func snapshot(f report.Finding) findingSnapshot {
	return findingSnapshot{
		rule: f.RuleID, line: f.StartLine, score: f.ConfidenceScore,
		level: f.ConfidenceLevel, reasons: strings.Join(f.ConfidenceReasons, "|"),
	}
}

func snapshots(in []report.Finding) []findingSnapshot {
	out := make([]findingSnapshot, 0, len(in))
	for _, f := range in {
		out = append(out, snapshot(f))
	}
	return out
}

// TestDeterministicAcrossRunsAndOrder is hard constraint #3: repeated scans of
// the same input produce identical findings, independent of map iteration.
func TestDeterministicAcrossRunsAndOrder(t *testing.T) {
	run := func() []findingSnapshot {
		d, _ := newJointDetector(t)
		findings := d.Detect(Fragment{
			FilePath: "multi/config.txt",
			Raw: `token = "ghp_K2mQx7"
secret = "Xq8vZm3kPw2nRt6yHb9cLd4fGj7sNk5p01"
secret = "Xq8vZm3kPw2nRt6yHb9cLd4fGj7sNk5p02"
build = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
`,
		})
		return snapshots(findings)
	}

	first := run()
	for i := 0; i < 5; i++ {
		assert.Equal(t, first, run(), "scan output must be stable across repeated runs")
	}
}

// TestIncrementalMatchesFullScanForSameFile is coverage #6: scanning the file
// alone (incremental) versus inside a larger batch yields the same decision.
func TestIncrementalMatchesFullScanForSameFile(t *testing.T) {
	target := Fragment{
		FilePath: "svc/config.yaml",
		Raw:      `token = "ghp_K2mQx7"` + "\n",
	}
	other := Fragment{
		FilePath: "svc/other.yaml",
		Raw:      `secret = "Xq8vZm3kPw2nRt6yHb9cLd4fGj7sNk5p01"` + "\n",
	}

	scanOne := func() []findingSnapshot {
		d, _ := newJointDetector(t)
		return snapshots(d.Detect(target))
	}
	scanBatch := func() []findingSnapshot {
		d, _ := newJointDetector(t)
		_ = d.Detect(other)
		return snapshots(d.Detect(target))
	}

	assert.Equal(t, scanOne(), scanBatch(),
		"the same file must get the same verdict whether scanned alone or with neighbors")
}

// TestMarksSuppressAndRevoke is coverage #8: a suppressed fingerprint is
// honored on later scans, and revoking the mark restores the finding.
func TestMarksSuppressAndRevoke(t *testing.T) {
	d, marksDir := newJointDetector(t)
	fragment := Fragment{
		FilePath: "svc/config.yaml",
		Raw:      `token = "ghp_K2mQx7"` + "\n",
	}

	first := d.Detect(fragment)
	require.Len(t, first, 1)
	fp := "svc/config.yaml:short-prefixed-token:" + strconv.Itoa(first[0].StartLine)

	// Persist a suppression; a fresh detector (next scan) must honor it.
	marksPath := filepath.Join(marksDir, "marks.json")
	store, err := NewMarksStore(marksPath)
	require.NoError(t, err)
	require.NoError(t, store.Suppress(fp, "rotated non-secret identifier"))

	d2, _ := newJointDetectorAt(t, d.Config, marksPath)
	assert.Empty(t, d2.Detect(fragment), "suppressed mark must be reused by the next scan")

	// Revoke, then the finding must return with an audit reason.
	require.NoError(t, store.Revoke(fp))
	d3, _ := newJointDetectorAt(t, d.Config, marksPath)
	restored := d3.Detect(fragment)
	require.Len(t, restored, 1)
	assert.Contains(t, restored[0].ConfidenceReasons, "mark:revoked")
}

// TestJointModeRedactsSecretsAtBoundary checks hard constraint #4: the
// reporting boundary (Findings(), which feeds every reporter) never returns
// raw secret material — even if a config tries to set redact_secrets=false.
func TestJointModeRedactsSecretsAtBoundary(t *testing.T) {
	cfg := loadConfidenceTestConfig(t)
	cfg.Confidence.RedactSecrets = false // must be ignored at the output boundary
	cfg.Confidence.Marks.Path = filepath.Join(t.TempDir(), "marks.json")
	d := NewDetector(cfg)
	require.NoError(t, d.EnableConfidence())

	fragment := Fragment{FilePath: "svc/config.yaml", Raw: `token = "ghp_K2mQx7"` + "\n"}
	for _, f := range d.Detect(fragment) {
		d.AddFinding(f)
	}
	require.NotEmpty(t, d.Findings())
	for _, f := range d.Findings() {
		assert.NotContains(t, f.Secret, "ghp_", "raw secret must be redacted at the output boundary")
		assert.NotEqual(t, "ghp_K2mQx7", f.Match)
		assert.NotEmpty(t, f.Fingerprint, "location/fingerprint must still be present")
	}

	// Detect() stays usable programmatically and is intentionally not redacted,
	// while still carrying the explainable confidence metadata.
	direct := d.Detect(fragment)
	require.Len(t, direct, 1)
	assert.Equal(t, "ghp_K2mQx7", direct[0].Secret, "in-process API keeps the value for programmatic use")
	assert.NotEmpty(t, direct[0].ConfidenceReasons)
}

// TestDegradedConfigFallsBackToDefaults is failure case #1: an unreadable
// confidence config degrades to built-in defaults and reports the condition.
func TestDegradedConfigFallsBackToDefaults(t *testing.T) {
	cfg, degraded := config.LoadConfidenceConfig(filepath.Join(t.TempDir(), "missing.toml"))
	require.NotNil(t, degraded, "missing file must be reported as degraded, not fatal")
	assert.False(t, degraded.HardReject)
	assert.True(t, cfg.Enabled, "degraded config still enables the engine on defaults")
	assert.InDelta(t, config.DefaultConfidenceConfig().Decision.ReportThreshold,
		cfg.Decision.ReportThreshold, 1e-9)
}

// TestSchemaVersionMismatchRejected is failure case #4: an unsupported schema
// version is hard-rejected instead of silently interpreted.
func TestSchemaVersionMismatchRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad-schema.toml")
	require.NoError(t, os.WriteFile(path, []byte(
		`enabled = true
schema_version = "999"
`), 0o600))

	_, degraded := config.LoadConfidenceConfig(path)
	require.NotNil(t, degraded)
	assert.True(t, degraded.HardReject, "schema mismatch must be a hard reject")
}

// TestFileParseFailureDoesNotAbortBatch is failure case #2: an unreadable file
// in a directory scan is skipped while the rest of the batch still completes.
func TestFileParseFailureDoesNotAbortBatch(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	require.NoError(t, os.WriteFile(good, []byte(`token = "ghp_K2mQx7"`+"\n"), 0o600))
	bad := filepath.Join(dir, "denied.yaml")
	require.NoError(t, os.WriteFile(bad, []byte(`token = "ghp_K2mQx7"`+"\n"), 0o600))
	require.NoError(t, os.Chmod(bad, 0o000))
	t.Cleanup(func() { _ = os.Chmod(bad, 0o600) })

	// Root can read regardless of permissions, so skip rather than get a
	// misleading pass when running privileged.
	if os.Geteuid() == 0 {
		t.Skip("permission-based skip cannot be asserted as root")
	}

	d, _ := newJointDetector(t)
	findings, err := d.DetectSource(context.Background(), &sources.Files{
		Config: &d.Config,
		Path:   dir,
		Sema:   d.Sema,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, findings, "a single unreadable file must not lose the whole batch")
}
