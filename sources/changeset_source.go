package sources

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
)

// ChangesetSource yields fragments for the scannable files of a Changeset.
//
// Files are visited in the changeset's stable (lexicographic) order and are
// scanned one at a time so that identical inputs always produce
// byte-identical reports. The same File source used by directory scans drives
// the actual fragment creation, which means binary detection, archive
// handling and rule matching are identical to full scans.
type ChangesetSource struct {
	// Changeset is the resolved set of files to scan. Deleted entries are
	// automatically skipped.
	Changeset *Changeset

	// RepoPath is the path to the git repository (or working tree root).
	RepoPath string

	// Config is used for path allowlists and archive handling.
	Config *config.Config

	// MaxArchiveDepth limits how deep archives are traversed.
	MaxArchiveDepth int

	// Preimage switches the source to reading the file content *before* the
	// change. It is used internally to classify rule-driven re-introductions.
	// When true, renamed files are read from their old path at the base
	// revision and files without a base revision are skipped.
	Preimage bool
}

var _ Source = (*ChangesetSource)(nil)

// Fragments implements Source.
func (s *ChangesetSource) Fragments(ctx context.Context, yield FragmentsFunc) error {
	if s.Changeset == nil {
		return nil
	}

	// Reuse one batch process for every blob in the changeset so large
	// revision ranges do not pay a process fork per file.
	var batch *BatchBlobReader
	if s.needsBlobReads() {
		var err error
		batch, err = NewBatchBlobReader(ctx, s.RepoPath)
		if err != nil {
			return err
		}
		defer func() { _ = batch.Close() }()
	}

	for _, change := range s.Changeset.Files {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if change.Kind == ChangeDeleted {
			logging.Debug().Str("path", change.Path).Msg("skipping deleted file")
			continue
		}

		path := change.Path
		if s.Preimage {
			if change.BaseRevision == "" {
				logging.Trace().Str("path", change.Path).Msg("no base revision, skipping preimage")
				continue
			}
			if change.OldPath != "" {
				path = change.OldPath
			}
		}

		reader, err := s.openReader(batch, change, path)
		if err != nil {
			// A changeset may reference a file that has since disappeared
			// (force-push, concurrent checkout, stale stdin list). Record and
			// skip instead of aborting the whole scan.
			logging.Warn().Err(err).Str("path", path).Msg("skipping file: content is not available")
			if yieldErr := yield(Fragment{FilePath: path}, err); yieldErr != nil {
				return yieldErr
			}
			continue
		}

		file := File{
			Content:         reader,
			Path:            path,
			Config:          s.Config,
			MaxArchiveDepth: s.MaxArchiveDepth,
		}

		err = file.Fragments(ctx, yield)
		_ = reader.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

// needsBlobReads reports whether any scannable change requires a git blob
// instead of a working tree read.
func (s *ChangesetSource) needsBlobReads() bool {
	for _, change := range s.Changeset.Files {
		if change.Kind == ChangeDeleted {
			continue
		}
		revision := change.TargetRevision
		if s.Preimage {
			revision = change.BaseRevision
		}
		if revision != "" {
			return true
		}
	}
	return false
}

// openReader returns a content reader for the given change. Git revision
// changesets read blobs through `git cat-file`; working tree and stdin
// changesets read from the filesystem.
func (s *ChangesetSource) openReader(batch *BatchBlobReader, change FileChange, path string) (io.ReadCloser, error) {
	revision := change.TargetRevision
	if s.Preimage {
		revision = change.BaseRevision
	}

	if revision != "" {
		if batch != nil {
			content, err := batch.Blob(revision, path)
			if err != nil {
				return nil, err
			}
			return io.NopCloser(bytes.NewReader(content)), nil
		}
		return nil, fmt.Errorf("no blob reader available for %s:%s", revision, path)
	}

	absolutePath := filepath.Join(s.RepoPath, filepath.FromSlash(path))
	file, err := os.Open(absolutePath)
	if err != nil {
		return nil, fmt.Errorf("could not open %s: %w", path, err)
	}
	return file, nil
}
