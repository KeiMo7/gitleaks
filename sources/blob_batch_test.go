package sources

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBatchBlobReader(t *testing.T) {
	repo := newGitRepo(t)
	gitCommit(t, repo, "initial", map[string]string{
		"main.go":     "package main\n",
		"nested/a.go": "package nested\n",
	})

	reader, err := NewBatchBlobReader(context.Background(), repo)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reader.Close() })

	content, err := reader.Blob("HEAD", "main.go")
	require.NoError(t, err)
	assert.Equal(t, "package main\n", string(content))

	// Repeated requests reuse the same process.
	content, err = reader.Blob("HEAD", "nested/a.go")
	require.NoError(t, err)
	assert.Equal(t, "package nested\n", string(content))

	// A missing object is reported as an error instead of crashing the process.
	if _, err = reader.Blob("HEAD", "does/not/exist.go"); assert.Error(t, err) {
		assert.Contains(t, err.Error(), "missing")
	}

	// The process stays usable after a missing object.
	content, err = reader.Blob("HEAD", "main.go")
	require.NoError(t, err)
	assert.Equal(t, "package main\n", string(content))

	require.NoError(t, reader.Close())

	// Operations after close fail cleanly rather than panicking.
	_, err = reader.Blob("HEAD", "main.go")
	assert.Error(t, err)
}

func TestChangesetSourceSkipsMissingBlob(t *testing.T) {
	ctx := context.Background()
	repo := newGitRepo(t)
	gitCommit(t, repo, "initial", map[string]string{"main.go": "package main\n"})

	// A fabricated change set pointing at a revision/path combination that
	// does not exist must be skipped, not abort the scan.
	changeset := &Changeset{
		repoPath: repo,
		Files: []FileChange{
			{Kind: ChangeModified, Path: "ghost.go", TargetRevision: "HEAD"},
		},
	}

	source := &ChangesetSource{
		Changeset: changeset,
		RepoPath:  repo,
	}

	var yielded int
	err := source.Fragments(ctx, func(fragment Fragment, fragmentErr error) error {
		yielded++
		if fragmentErr != nil {
			assert.Contains(t, fragmentErr.Error(), "ghost.go")
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, yielded)
}
