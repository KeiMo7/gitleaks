package detect

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

const testSecret = "AKIALALEMEL33243OLIA"

// changesetTestConfig is a minimal rule set reused by every incremental test
// so no testdata or external config is involved.
func changesetTestConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Config{
		Rules:    make(map[string]config.Rule),
		Keywords: make(map[string]struct{}),
	}

	awsRule := config.Rule{
		RuleID:      "aws-access-key",
		Description: "AWS Access Key",
		Regex:       regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}`),
		Keywords:    []string{"akia", "asia"},
		Tags:        []string{"AWS", "key"},
	}
	cfg.Rules[awsRule.RuleID] = awsRule
	cfg.Keywords["akia"] = struct{}{}
	cfg.Keywords["asia"] = struct{}{}

	return cfg
}

func newChangesetDetector(t *testing.T, cfg config.Config) *Detector {
	t.Helper()
	detector := NewDetector(cfg)
	detector.MaxDecodeDepth = maxDecodeDepth
	return detector
}

func fullDirectoryScan(t *testing.T, repo string, cfg config.Config) []report.Finding {
	t.Helper()
	detector := newChangesetDetector(t, cfg)
	findings, err := detector.DetectSource(context.Background(), &sources.Files{
		Config:          &cfg,
		MaxFileSize:     detector.MaxTargetMegaBytes * 1_000_000,
		Path:            repo,
		Sema:            detector.Sema,
		MaxArchiveDepth: detector.MaxArchiveDepth,
	})
	require.NoError(t, err)
	report.SortFindings(findings)
	// Directory scans report absolute paths while changeset scans report
	// repository-relative paths. Normalize for the parity comparison.
	for index := range findings {
		findings[index].File = strings.TrimPrefix(findings[index].File, filepath.Clean(repo)+string(os.PathSeparator))
		findings[index].Fingerprint = ""
	}
	return findings
}

func assertParity(t *testing.T, full, incremental []report.Finding) {
	t.Helper()
	// Full directory scans include .git internals? No: .git contents are
	// binary/ignored here. Compare on the stable identity fields.
	for index := range incremental {
		incremental[index].Fingerprint = ""
	}
	assert.Equal(t, fingerprintSet(full), fingerprintSet(incremental))
}

func fingerprintSet(findings []report.Finding) map[string]report.Finding {
	set := make(map[string]report.Finding, len(findings))
	for _, finding := range findings {
		key := strings.Join([]string{
			finding.File,
			finding.RuleID,
			strconv.Itoa(finding.StartLine),
			strconv.Itoa(finding.StartColumn),
			strconv.Itoa(finding.EndLine),
			strconv.Itoa(finding.EndColumn),
			finding.Secret,
		}, "|")
		set[key] = finding
	}
	return set
}

func runGit(t *testing.T, repo string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = repo
	combined, err := cmd.CombinedOutput()
	require.NoError(t, err, string(combined))
}

func writeRepoFile(t *testing.T, repo, path, content string) {
	t.Helper()
	full := filepath.Join(repo, filepath.FromSlash(path))
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
	require.NoError(t, os.WriteFile(full, []byte(content), 0o600))
}

func setupChangesetRepo(t *testing.T) (repo, baseSHA string) {
	t.Helper()
	repo = t.TempDir()
	runGit(t, repo, "init", "-q", "-b", "main")
	runGit(t, repo, "config", "user.name", "Gitleaks Test")
	runGit(t, repo, "config", "user.email", "gitleaks@example.com")
	runGit(t, repo, "config", "commit.gpgsign", "false")

	writeRepoFile(t, repo, "main.go", "package main\n\nfunc main() {}\n")
	writeRepoFile(t, repo, "docs/readme.md", "# docs\n")
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-q", "-m", "initial")

	out, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	require.NoError(t, err)
	return repo, strings.TrimSpace(string(out))
}

func commitAll(t *testing.T, repo, message string) {
	t.Helper()
	runGit(t, repo, "add", "-A")
	runGit(t, repo, "commit", "-q", "-m", message)
}

func TestChangesetScenarios(t *testing.T) {
	ctx := context.Background()

	t.Run("new file including new directory", func(t *testing.T) {
		repo, baseSHA := setupChangesetRepo(t)
		writeRepoFile(t, repo, "brand/new/dir/secret.go", "package dir\n\nconst token = \""+testSecret+"\"\n")
		commitAll(t, repo, "add secret")

		cfg := changesetTestConfig(t)
		changeset, err := sources.NewChangesetFromRanges(ctx, repo, []string{baseSHA + "..HEAD"})
		require.NoError(t, err)

		detector := newChangesetDetector(t, cfg)
		findings, err := detector.DetectChangeset(ctx, changeset, false)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "brand/new/dir/secret.go", findings[0].File)
		assert.Equal(t, "aws-access-key", findings[0].RuleID)
		assert.Equal(t, 3, findings[0].StartLine)
	})

	t.Run("modified file only scans changed content with full scan parity", func(t *testing.T) {
		repo, baseSHA := setupChangesetRepo(t)
		writeRepoFile(t, repo, "main.go", "package main\n\nconst key = \""+testSecret+"\"\n\nfunc main() {}\n")
		commitAll(t, repo, "modify")

		cfg := changesetTestConfig(t)
		changeset, err := sources.NewChangesetFromRanges(ctx, repo, []string{baseSHA + "..HEAD"})
		require.NoError(t, err)

		detector := newChangesetDetector(t, cfg)
		incremental, err := detector.DetectChangeset(ctx, changeset, false)
		require.NoError(t, err)

		full := fullDirectoryScan(t, repo, cfg)
		require.Len(t, full, 1)
		assertParity(t, full, incremental)
	})

	t.Run("deleted file produces no findings", func(t *testing.T) {
		repo, baseSHA := setupChangesetRepo(t)
		writeRepoFile(t, repo, "doomed.go", "const key = \""+testSecret+"\"\n")
		commitAll(t, repo, "add doomed")

		require.NoError(t, os.Remove(filepath.Join(repo, "doomed.go")))
		commitAll(t, repo, "delete doomed")

		cfg := changesetTestConfig(t)
		changeset, err := sources.NewChangesetFromRanges(ctx, repo, []string{baseSHA + "..HEAD"})
		require.NoError(t, err)

		detector := newChangesetDetector(t, cfg)
		findings, err := detector.DetectChangeset(ctx, changeset, false)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("rename follows old path history", func(t *testing.T) {
		repo, _ := setupChangesetRepo(t)
		// The file must exist at the base for git to classify the move as a
		// rename instead of an add plus a delete.
		writeRepoFile(t, repo, "old.go", "const key = \""+testSecret+"\"\n")
		commitAll(t, repo, "add old")
		baseBeforeRename, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
		require.NoError(t, err)

		runGit(t, repo, "mv", "old.go", "new.go")
		commitAll(t, repo, "rename")

		cfg := changesetTestConfig(t)
		changeset, err := sources.NewChangesetFromRanges(ctx, repo, []string{strings.TrimSpace(string(baseBeforeRename)) + "..HEAD"})
		require.NoError(t, err)
		require.Equal(t, sources.ChangeRenamed, changeset.Files[0].Kind)

		// A .gitleaksignore entry anchored at the old path still suppresses
		// the finding after the rename.
		writeRepoFile(t, repo, ".gitleaksignore", "old.go:aws-access-key:1\n")

		detector := newChangesetDetector(t, cfg)
		require.NoError(t, detector.AddGitleaksIgnore(filepath.Join(repo, ".gitleaksignore")))
		findings, err := detector.DetectChangeset(ctx, changeset, false)
		require.NoError(t, err)
		assert.Empty(t, findings)

		// Without the ignore entry the renamed file is still scanned.
		detector = newChangesetDetector(t, cfg)
		findings, err = detector.DetectChangeset(ctx, changeset, false)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "new.go", findings[0].File)
	})

	t.Run("mixed changeset", func(t *testing.T) {
		repo, baseSHA := setupChangesetRepo(t)
		writeRepoFile(t, repo, "added.go", "const a = \""+testSecret+"\"\n")
		writeRepoFile(t, repo, "main.go", "package main\n\nconst b = \""+testSecret+"\"\n")
		writeRepoFile(t, repo, "removed.txt", "nothing secret\n")
		commitAll(t, repo, "mixed")
		require.NoError(t, os.Remove(filepath.Join(repo, "removed.txt")))
		commitAll(t, repo, "remove")

		cfg := changesetTestConfig(t)
		changeset, err := sources.NewChangesetFromRanges(ctx, repo, []string{baseSHA + "..HEAD"})
		require.NoError(t, err)

		detector := newChangesetDetector(t, cfg)
		findings, err := detector.DetectChangeset(ctx, changeset, false)
		require.NoError(t, err)

		files := make(map[string]bool)
		for _, finding := range findings {
			files[finding.File] = true
		}
		assert.True(t, files["added.go"])
		assert.True(t, files["main.go"])
		assert.False(t, files["removed.txt"])

		full := fullDirectoryScan(t, repo, cfg)
		assertParity(t, full, findings)
	})

	t.Run("empty changeset succeeds with no findings", func(t *testing.T) {
		repo, _ := setupChangesetRepo(t)
		cfg := changesetTestConfig(t)

		changeset, err := sources.NewChangesetFromDiff(ctx, repo, false)
		require.NoError(t, err)

		detector := newChangesetDetector(t, cfg)
		findings, err := detector.DetectChangeset(ctx, changeset, false)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("missing file in changeset is skipped", func(t *testing.T) {
		repo, _ := setupChangesetRepo(t)
		cfg := changesetTestConfig(t)

		changeset, err := sources.NewChangesetFromReader(repo, strings.NewReader("main.go\ngone/missing.go\n"))
		require.NoError(t, err)

		detector := newChangesetDetector(t, cfg)
		findings, err := detector.DetectChangeset(ctx, changeset, false)
		require.NoError(t, err)
		assert.Empty(t, findings)
	})
}

func TestChangesetDeterministicOutput(t *testing.T) {
	ctx := context.Background()
	repo, baseSHA := setupChangesetRepo(t)
	writeRepoFile(t, repo, "a.go", "const a = \""+testSecret+"\"\n")
	writeRepoFile(t, repo, "b.go", "const b = \""+testSecret+"\"\n")
	writeRepoFile(t, repo, "c.go", "const c = \""+testSecret+"\"\n")
	commitAll(t, repo, "many")

	cfg := changesetTestConfig(t)

	runOnce := func() []report.Finding {
		changeset, err := sources.NewChangesetFromRanges(ctx, repo, []string{baseSHA + "..HEAD"})
		require.NoError(t, err)
		detector := newChangesetDetector(t, cfg)
		findings, err := detector.DetectChangeset(ctx, changeset, false)
		require.NoError(t, err)
		report.SortFindings(findings)
		return findings
	}

	first := runOnce()
	second := runOnce()
	require.Len(t, first, 3)
	assert.Equal(t, first, second)
}
