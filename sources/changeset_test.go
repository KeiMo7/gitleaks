package sources

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseNameStatus(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		raw      string
		expected []nameStatusEntry
	}{
		"added file in new directory": {
			raw: "A\x00new/dir/file.go\x00",
			expected: []nameStatusEntry{
				{kind: ChangeAdded, path: "new/dir/file.go"},
			},
		},
		"modified file": {
			raw: "M\x00main.go\x00",
			expected: []nameStatusEntry{
				{kind: ChangeModified, path: "main.go"},
			},
		},
		"deleted file": {
			raw: "D\x00removed.txt\x00",
			expected: []nameStatusEntry{
				{kind: ChangeDeleted, path: "removed.txt"},
			},
		},
		"rename with similarity": {
			raw: "R096\x00old/path.go\x00new/path.go\x00",
			expected: []nameStatusEntry{
				{kind: ChangeRenamed, oldPath: "old/path.go", path: "new/path.go"},
			},
		},
		"mixed changeset": {
			raw: strings.Join([]string{
				"A", "new.go",
				"M", "main.go",
				"D", "gone.txt",
				"R100", "old.go", "renamed.go",
				"",
			}, "\x00"),
			expected: []nameStatusEntry{
				{kind: ChangeAdded, path: "new.go"},
				{kind: ChangeModified, path: "main.go"},
				{kind: ChangeDeleted, path: "gone.txt"},
				{kind: ChangeRenamed, oldPath: "old.go", path: "renamed.go"},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, parseNameStatus([]byte(tt.raw)))
		})
	}
}

func TestParseBaseTarget(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		input  string
		base   string
		target string
	}{
		"double dot range":       {input: "main..HEAD", base: "main", target: "HEAD"},
		"sha range":              {input: "abc123..def456", base: "abc123", target: "def456"},
		"trailing dots defaults": {input: "main..", base: "main", target: "HEAD"},
		"single revision":        {input: "abc123", base: "", target: "abc123"},
		"caret revision":         {input: "^abc123", base: "", target: "abc123"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			base, target := ParseBaseTarget(tt.input)
			assert.Equal(t, tt.base, base)
			assert.Equal(t, tt.target, target)
		})
	}
}

func TestParseDiffArgs(t *testing.T) {
	t.Parallel()

	assert.Equal(t, []string{"main", "HEAD"}, parseDiffArgs("main..HEAD"))
	assert.Equal(t, []string{emptyTreeRevision, "abc123"}, parseDiffArgs("abc123"))
	assert.Equal(t, []string{emptyTreeRevision, "abc123"}, parseDiffArgs("^abc123"))
}

func TestChangesetScannableAndAliases(t *testing.T) {
	t.Parallel()

	changeset := &Changeset{Files: []FileChange{
		{Kind: ChangeAdded, Path: "a/new.go"},
		{Kind: ChangeDeleted, Path: "b/gone.txt"},
		{Kind: ChangeRenamed, Path: "c/new.go", OldPath: "c/old.go"},
		{Kind: ChangeModified, Path: "d/main.go"},
	}}

	scannable := changeset.Scannable()
	require.Len(t, scannable, 3)
	for _, change := range scannable {
		assert.NotEqual(t, ChangeDeleted, change.Kind)
	}

	assert.Equal(t, map[string]string{"c/new.go": "c/old.go"}, changeset.RenameAliases())
}

// newGitRepo builds a throwaway git repository with deterministic identity.
func newGitRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()

	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		combined, err := cmd.CombinedOutput()
		require.NoError(t, err, string(combined))
	}

	run("init", "-q", "-b", "main")
	run("config", "user.name", "Gitleaks Test")
	run("config", "user.email", "gitleaks@example.com")
	run("config", "commit.gpgsign", "false")

	return repo
}

func gitCommit(t *testing.T, repo, message string, paths map[string]string) {
	t.Helper()
	for path, content := range paths {
		full := filepath.Join(repo, filepath.FromSlash(path))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o600))
		cmd := exec.Command("git", "add", "--", path)
		cmd.Dir = repo
		combined, err := cmd.CombinedOutput()
		require.NoError(t, err, string(combined))
	}
	cmd := exec.Command("git", "commit", "-q", "-m", message)
	cmd.Dir = repo
	combined, err := cmd.CombinedOutput()
	require.NoError(t, err, string(combined))
}

func gitRm(t *testing.T, repo, path string) {
	t.Helper()
	cmd := exec.Command("git", "rm", "-q", "--", path)
	cmd.Dir = repo
	combined, err := cmd.CombinedOutput()
	require.NoError(t, err, string(combined))
}

func gitMV(t *testing.T, repo, oldPath, newPath string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(repo, filepath.Dir(newPath)), 0o755))
	cmd := exec.Command("git", "mv", "--", oldPath, newPath)
	cmd.Dir = repo
	combined, err := cmd.CombinedOutput()
	require.NoError(t, err, string(combined))
}

func findChange(changes []FileChange, path string) (FileChange, bool) {
	for _, change := range changes {
		if change.Path == path {
			return change, true
		}
	}
	return FileChange{}, false
}

func TestNewChangesetFromRanges(t *testing.T) {
	repo := newGitRepo(t)
	gitCommit(t, repo, "initial", map[string]string{
		"main.go":       "package main\n",
		"old/rename.go": "package old\n",
	})
	base, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	require.NoError(t, err)
	baseSHA := strings.TrimSpace(string(base))

	gitCommit(t, repo, "changes", map[string]string{
		"new/dir/new.go": "package new\n",
		"main.go":        "package main // changed\n",
	})
	gitRm(t, repo, "old/rename.go")
	gitCommit(t, repo, "delete", nil)

	changeset, err := NewChangesetFromRanges(context.Background(), repo, []string{baseSHA + "..HEAD"})
	require.NoError(t, err)

	// Deterministic ordering.
	for i := 1; i < len(changeset.Files); i++ {
		assert.Less(t, changeset.Files[i-1].Path, changeset.Files[i].Path)
	}

	added, ok := findChange(changeset.Files, "new/dir/new.go")
	require.True(t, ok)
	assert.Equal(t, ChangeAdded, added.Kind)

	modified, ok := findChange(changeset.Files, "main.go")
	require.True(t, ok)
	assert.Equal(t, ChangeModified, modified.Kind)

	deleted, ok := findChange(changeset.Files, "old/rename.go")
	require.True(t, ok)
	assert.Equal(t, ChangeDeleted, deleted.Kind)
}

func TestNewChangesetFromRangesRename(t *testing.T) {
	repo := newGitRepo(t)
	gitCommit(t, repo, "initial", map[string]string{"old.go": "package old\n"})
	base, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	require.NoError(t, err)

	gitMV(t, repo, "old.go", "new.go")
	cmd := exec.Command("git", "commit", "-q", "-m", "rename")
	cmd.Dir = repo
	combined, err := cmd.CombinedOutput()
	require.NoError(t, err, string(combined))

	changeset, err := NewChangesetFromRanges(context.Background(), repo,
		[]string{strings.TrimSpace(string(base)) + "..HEAD"})
	require.NoError(t, err)

	change, ok := findChange(changeset.Files, "new.go")
	require.True(t, ok)
	assert.Equal(t, ChangeRenamed, change.Kind)
	assert.Equal(t, "old.go", change.OldPath)
}

func TestNewChangesetFromRangesUnionIsDeduplicated(t *testing.T) {
	repo := newGitRepo(t)
	gitCommit(t, repo, "initial", map[string]string{"main.go": "v1\n"})
	first, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	require.NoError(t, err)

	gitCommit(t, repo, "second", map[string]string{"main.go": "v2\n"})
	second, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	require.NoError(t, err)

	gitCommit(t, repo, "third", map[string]string{"main.go": "v3\n", "other.go": "x\n"})

	// Overlapping ranges both touch main.go; it must appear exactly once.
	changeset, err := NewChangesetFromRanges(context.Background(), repo, []string{
		strings.TrimSpace(string(first)) + "..HEAD",
		strings.TrimSpace(string(second)) + "..HEAD",
	})
	require.NoError(t, err)

	count := 0
	for _, change := range changeset.Files {
		if change.Path == "main.go" {
			count++
		}
	}
	assert.Equal(t, 1, count)
}

func TestNewChangesetFromDiffAndReader(t *testing.T) {
	repo := newGitRepo(t)
	gitCommit(t, repo, "initial", map[string]string{"main.go": "v1\n", "gone.txt": "bye\n"})

	// Unstaged modifications, a deletion and a new file.
	require.NoError(t, os.WriteFile(filepath.Join(repo, "main.go"), []byte("v2\n"), 0o600))
	require.NoError(t, os.Remove(filepath.Join(repo, "gone.txt")))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "fresh.txt"), []byte("hi\n"), 0o600))

	t.Run("unstaged diff", func(t *testing.T) {
		changeset, err := NewChangesetFromDiff(context.Background(), repo, false)
		require.NoError(t, err)
		assert.True(t, changeset.Files[0].Path <= changeset.Files[len(changeset.Files)-1].Path)

		_, ok := findChange(changeset.Files, "main.go")
		assert.True(t, ok)
		_, ok = findChange(changeset.Files, "gone.txt")
		assert.True(t, ok)
	})

	t.Run("stdin reader", func(t *testing.T) {
		input := "main.go\nmissing/does-not-exist.txt\n"
		changeset, err := NewChangesetFromReader(repo, strings.NewReader(input))
		require.NoError(t, err)
		assert.True(t, changeset.FromStdin)

		missing, ok := findChange(changeset.Files, "missing/does-not-exist.txt")
		require.True(t, ok)
		assert.Equal(t, ChangeDeleted, missing.Kind)

		// Determinism: parsing twice yields identical ordering.
		again, err := NewChangesetFromReader(repo, strings.NewReader(input))
		require.NoError(t, err)
		assert.Equal(t, changeset.Files, again.Files)
	})

	t.Run("staged diff", func(t *testing.T) {
		cmd := exec.Command("git", "add", "main.go")
		cmd.Dir = repo
		require.NoError(t, cmd.Run())

		changeset, err := NewChangesetFromDiff(context.Background(), repo, true)
		require.NoError(t, err)
		assert.True(t, changeset.Staged)
		_, ok := findChange(changeset.Files, "main.go")
		assert.True(t, ok)
	})
}

func TestEmptyChangeset(t *testing.T) {
	repo := newGitRepo(t)
	gitCommit(t, repo, "initial", map[string]string{"main.go": "v1\n"})

	changeset, err := NewChangesetFromDiff(context.Background(), repo, false)
	require.NoError(t, err)
	assert.Empty(t, changeset.Files)
	assert.Empty(t, changeset.Scannable())
}
