package detect

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// narrowConfig only matches a different token family, used to simulate a rule
// update that starts flagging the existing AWS token.
func narrowConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Config{
		Rules:    make(map[string]config.Rule),
		Keywords: make(map[string]struct{}),
	}
	rule := config.Rule{
		RuleID:      "gcp-api-key",
		Description: "GCP API Key",
		Regex:       regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		Keywords:    []string{"aiza"},
		Tags:        []string{"gcp"},
	}
	cfg.Rules[rule.RuleID] = rule
	cfg.Keywords["aiza"] = struct{}{}
	return cfg
}

func TestRuleChangeReintroduction(t *testing.T) {
	ctx := context.Background()
	repo, _ := setupChangesetRepo(t)

	// The secret exists at the base revision.
	writeRepoFile(t, repo, "config/app.yaml", "token: \""+testSecret+"\"\n")
	commitAll(t, repo, "add config with token")
	baseSHA, err := gitRevParse(repo)
	require.NoError(t, err)

	// The changeset only touches an unrelated line of the same file.
	writeRepoFile(t, repo, "config/app.yaml", "name: demo\ntoken: \""+testSecret+"\"\n")
	commitAll(t, repo, "unrelated edit")

	// Old rules did not flag anything; the updated rules flag the token.
	oldCfg := narrowConfig(t)
	newCfg := changesetTestConfig(t)

	changeset, err := sources.NewChangesetFromRanges(ctx, repo, []string{baseSHA + "..HEAD"})
	require.NoError(t, err)

	// Sanity check: the old rule set reports nothing at both revisions.
	oldDetector := newChangesetDetector(t, oldCfg)
	oldFindings, err := oldDetector.DetectChangeset(ctx, changeset, false)
	require.NoError(t, err)
	assert.Empty(t, oldFindings)

	// With rulesChanged=true the finding is classified as a rule-driven
	// re-introduction, not a newly introduced secret.
	detector := newChangesetDetector(t, newCfg)
	findings, err := detector.DetectChangeset(ctx, changeset, true)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.True(t, detector.IsRuleChange(findings[0]))
	require.Len(t, detector.RuleChangeFindings(), 1)

	// Without rule-change classification the same finding is considered new.
	plainDetector := newChangesetDetector(t, newCfg)
	plainFindings, err := plainDetector.DetectChangeset(ctx, changeset, false)
	require.NoError(t, err)
	require.Len(t, plainFindings, 1)
	assert.False(t, plainDetector.IsRuleChange(plainFindings[0]))
}

func TestBaselineMetaRoundTripAndValidation(t *testing.T) {
	cfg := changesetTestConfig(t)
	baselinePath := filepath.Join(t.TempDir(), "baseline.json")

	require.NoError(t, os.WriteFile(baselinePath, []byte("[]"), 0o600))
	require.NoError(t, WriteBaselineMeta(baselinePath, cfg))

	meta, ok, err := LoadBaselineMeta(baselinePath)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, BaselineMetaSchemaVersion, meta.SchemaVersion)
	assert.Equal(t, RulesChecksum(cfg), meta.RulesChecksum)

	// Checksum changes when a rule changes.
	other := narrowConfig(t)
	assert.NotEqual(t, RulesChecksum(cfg), RulesChecksum(other))

	// Path-only rules (nil Regex) must not panic the checksum.
	pathOnly := config.Config{
		Rules: map[string]config.Rule{
			"path-only": {
				RuleID: "path-only",
				Path:   regexp.MustCompile(`\.env$`),
			},
		},
		Keywords: map[string]struct{}{},
	}
	assert.NotEmpty(t, RulesChecksum(pathOnly))

	// Missing sidecar: ok=false, no error.
	missing := filepath.Join(t.TempDir(), "baseline.json")
	_, ok, err = LoadBaselineMeta(missing)
	require.NoError(t, err)
	assert.False(t, ok)

	// Corrupted sidecar: explicit error, never silently treated as empty.
	require.NoError(t, os.WriteFile(BaselineMetaPath(baselinePath), []byte("{not-json"), 0o600))
	_, _, err = LoadBaselineMeta(baselinePath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "corrupted")

	// Unsupported schema version: explicit error with guidance.
	require.NoError(t, os.WriteFile(BaselineMetaPath(baselinePath),
		[]byte(`{"schema_version":99,"rules_checksum":"x"}`), 0o600))
	_, _, err = LoadBaselineMeta(baselinePath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported schema version")
}

func TestBaselineAcrossRename(t *testing.T) {
	ctx := context.Background()
	repo, _ := setupChangesetRepo(t)
	writeRepoFile(t, repo, "old.go", "const key = \""+testSecret+"\"\n")
	commitAll(t, repo, "add old")

	beforeRename, err := gitRevParse(repo)
	require.NoError(t, err)
	runGit(t, repo, "mv", "old.go", "new.go")
	commitAll(t, repo, "rename")

	cfg := changesetTestConfig(t)

	changeset, err := sources.NewChangesetFromRanges(ctx, repo, []string{beforeRename + "..HEAD"})
	require.NoError(t, err)

	// Baseline captured at the old path, as produced by an earlier full scan.
	baseline := []report.Finding{baselineFinding("old.go")}
	detector := newChangesetDetector(t, cfg)
	detector.baseline = baseline
	findings, err := detector.DetectChangeset(ctx, changeset, false)
	require.NoError(t, err)
	assert.Empty(t, findings, "baseline entry at the old path must still apply after rename")

	// A baseline anchored only at the new path works too.
	detector = newChangesetDetector(t, cfg)
	detector.baseline = []report.Finding{baselineFinding("new.go")}
	findings, err = detector.DetectChangeset(ctx, changeset, false)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func baselineFinding(path string) report.Finding {
	return report.Finding{
		RuleID:      "aws-access-key",
		Description: "AWS Access Key",
		StartLine:   1,
		EndLine:     1,
		StartColumn: 14,
		EndColumn:   33,
		Line:        "const key = \"" + testSecret + "\"",
		Match:       testSecret,
		Secret:      testSecret,
		File:        path,
		Entropy:     3.0841837,
		Tags:        []string{"AWS", "key"},
	}
}

func gitRevParse(repo string) (string, error) {
	out, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	return strings.TrimSpace(string(out)), err
}
