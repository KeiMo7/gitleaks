package sources

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zricethezav/gitleaks/v8/logging"
)

// ChangeKind describes what happened to a file in a changeset.
type ChangeKind int

const (
	// ChangeAdded means the file is newly tracked (including files in new directories).
	ChangeAdded ChangeKind = iota
	// ChangeModified means an existing tracked file was modified.
	ChangeModified
	// ChangeDeleted means the file was removed and no longer exists at the target revision.
	ChangeDeleted
	// ChangeRenamed means the file was renamed; OldPath holds the previous path.
	ChangeRenamed
)

// String returns a stable, human readable representation of the ChangeKind.
func (k ChangeKind) String() string {
	switch k {
	case ChangeAdded:
		return "added"
	case ChangeModified:
		return "modified"
	case ChangeDeleted:
		return "deleted"
	case ChangeRenamed:
		return "renamed"
	default:
		return "unknown"
	}
}

// FileChange describes a single file inside a changeset.
type FileChange struct {
	// Kind is the type of change.
	Kind ChangeKind

	// Path is the path of the file after the change. It is empty for deletions.
	Path string

	// OldPath is the path of the file before the change. It is only set for renames.
	OldPath string

	// BaseRevision is the git revision the change is relative to. It is empty
	// for working tree and stdin based changesets.
	BaseRevision string

	// TargetRevision is the git revision the change is relative to. It is empty
	// for working tree and stdin based changesets.
	TargetRevision string
}

// Changeset is the de-duplicated, stably ordered set of files touched by one
// or more commit ranges or a file list read from stdin.
type Changeset struct {
	// Files holds the changes in a stable, lexicographic order keyed by Path.
	Files []FileChange

	// Ranges are the raw git revision ranges the changeset was built from.
	Ranges []string

	// FromStdin is true when the file list was provided on stdin.
	FromStdin bool

	// Staged is true when the working tree's index was used as the changeset.
	Staged bool

	// repoPath is the repository root used for filesystem and git invocations.
	repoPath string
}

// RepoPath returns the repository root the changeset was resolved against.
func (c *Changeset) RepoPath() string {
	if c == nil {
		return ""
	}
	return c.repoPath
}

// ParseBaseTarget splits a git revision range into a base revision and a
// target revision. The returned base revision is suitable for reading the
// pre-image of a file with `git cat-file blob`. An empty base means the file
// had no pre-image (e.g. a root commit).
func ParseBaseTarget(revisionRange string) (base string, target string) {
	r := strings.TrimSpace(revisionRange)
	switch {
	case strings.Contains(r, ".."):
		parts := strings.SplitN(r, "..", 2)
		base, target = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if target == "" {
			target = "HEAD"
		}
	case strings.HasPrefix(r, "^"):
		base = ""
		target = strings.TrimSpace(strings.TrimPrefix(r, "^"))
	default:
		// A single revision means "everything reachable from that revision up
		// to and including its root".
		base = ""
		target = r
	}
	return base, target
}

// NewChangesetFromRanges builds a changeset from one or more git revision
// ranges. Multiple ranges are unioned; the result is de-duplicated and stably
// ordered so two runs with the same input produce byte-identical output.
func NewChangesetFromRanges(ctx context.Context, repoPath string, revisionRanges []string) (*Changeset, error) {
	changeset := &Changeset{Ranges: append([]string(nil), revisionRanges...), repoPath: filepath.Clean(repoPath)}
	byPath := make(map[string]FileChange)

	for _, revisionRange := range revisionRanges {
		base, target := ParseBaseTarget(revisionRange)
		if target == "" {
			return nil, fmt.Errorf("could not determine target revision from range %q", revisionRange)
		}

		entries, err := gitNameStatus(ctx, repoPath, revisionRange)
		if err != nil {
			return nil, fmt.Errorf("could not resolve changeset for range %q: %w", revisionRange, err)
		}

		for _, entry := range entries {
			change := FileChange{
				Kind:           entry.kind,
				Path:           entry.path,
				OldPath:        entry.oldPath,
				BaseRevision:   base,
				TargetRevision: target,
			}
			mergeChange(byPath, change)
		}
	}

	changeset.Files = sortedChanges(byPath)
	return changeset, nil
}

// NewChangesetFromDiff builds a changeset from the working tree. When staged is
// true the index (staged changes) is used, otherwise unstaged changes are used.
func NewChangesetFromDiff(ctx context.Context, repoPath string, staged bool) (*Changeset, error) {
	args := []string{"-C", filepath.Clean(repoPath), "diff", "--name-status", "-z", "--no-ext-diff", "-M"}
	if staged {
		args = append(args, "--staged")
	}
	entries, err := runNameStatus(ctx, args)
	if err != nil {
		return nil, fmt.Errorf("could not resolve working tree changeset: %w", err)
	}

	byPath := make(map[string]FileChange)
	for _, entry := range entries {
		mergeChange(byPath, FileChange{Kind: entry.kind, Path: entry.path, OldPath: entry.oldPath})
	}

	return &Changeset{Files: sortedChanges(byPath), Staged: staged, repoPath: filepath.Clean(repoPath)}, nil
}

// NewChangesetFromReader builds a changeset from a newline (or NUL) separated
// list of file paths. Paths are interpreted relative to repoPath and are
// resolved against the working tree; deletions are detected by checking the
// filesystem. The input is de-duplicated and stably ordered.
func NewChangesetFromReader(repoPath string, reader io.Reader) (*Changeset, error) {
	scanner := bufio.NewScanner(reader)
	// File paths can be long; allow generous lines.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	byPath := make(map[string]FileChange)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		for _, path := range strings.Split(line, "\x00") {
			path = strings.TrimSpace(path)
			if path == "" {
				continue
			}
			kind := ChangeModified
			if _, err := os.Stat(filepath.Join(repoPath, path)); errors.Is(err, os.ErrNotExist) {
				kind = ChangeDeleted
			}
			mergeChange(byPath, FileChange{Kind: kind, Path: filepath.ToSlash(path)})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("could not read changeset file list: %w", err)
	}

	return &Changeset{Files: sortedChanges(byPath), FromStdin: true, repoPath: filepath.Clean(repoPath)}, nil
}

type nameStatusEntry struct {
	kind    ChangeKind
	path    string
	oldPath string
}

// gitNameStatus runs `git diff --name-status -z -M` for a revision range and
// parses the NUL-delimited output, including rename records.
func gitNameStatus(ctx context.Context, repoPath, revisionRange string) ([]nameStatusEntry, error) {
	args := []string{
		"-C", filepath.Clean(repoPath),
		"diff", "--name-status", "-z", "--no-ext-diff", "-M",
	}
	args = append(args, parseDiffArgs(revisionRange)...)
	return runNameStatus(ctx, args)
}

// parseDiffArgs converts a user supplied revision range into arguments
// accepted by `git diff`. A range such as A..B becomes `A B`.
func parseDiffArgs(revisionRange string) []string {
	r := strings.TrimSpace(revisionRange)
	if strings.Contains(r, "..") {
		parts := strings.SplitN(r, "..", 2)
		base, target := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if target == "" {
			target = "HEAD"
		}
		return []string{base, target}
	}
	// A single revision means "everything reachable from that revision up to
	// and including its root", so compare the git empty tree against it. A
	// bare `git diff <rev>` would instead diff the working tree.
	return []string{emptyTreeRevision, strings.TrimPrefix(r, "^")}
}

// emptyTreeRevision is the well-known SHA-1 of git's empty tree object. It
// exists in every repository without being fetched or created.
const emptyTreeRevision = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

func runNameStatus(ctx context.Context, args []string) ([]nameStatusEntry, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	logging.Debug().Msgf("executing: %s", cmd.String())

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}

	return parseNameStatus(stdout.Bytes()), nil
}

// parseNameStatus parses NUL-delimited `git diff --name-status -z` output.
//
// Regular records look like:  A\x00path\x00
// Rename/copy records look like: R100\x00oldpath\x00newpath\x00
func parseNameStatus(raw []byte) []nameStatusEntry {
	tokens := strings.Split(string(raw), "\x00")
	entries := make([]nameStatusEntry, 0, len(tokens)/2)

	for i := 0; i < len(tokens); {
		status := tokens[i]
		if status == "" {
			i++
			continue
		}

		letter := status[0]
		switch letter {
		case 'R', 'C':
			if i+2 >= len(tokens) {
				return entries
			}
			entries = append(entries, nameStatusEntry{
				kind:    ChangeRenamed,
				oldPath: filepath.ToSlash(tokens[i+1]),
				path:    filepath.ToSlash(tokens[i+2]),
			})
			i += 3
		case 'A':
			if i+1 >= len(tokens) {
				return entries
			}
			entries = append(entries, nameStatusEntry{kind: ChangeAdded, path: filepath.ToSlash(tokens[i+1])})
			i += 2
		case 'D':
			if i+1 >= len(tokens) {
				return entries
			}
			entries = append(entries, nameStatusEntry{kind: ChangeDeleted, path: filepath.ToSlash(tokens[i+1])})
			i += 2
		case 'M', 'T', 'U':
			if i+1 >= len(tokens) {
				return entries
			}
			entries = append(entries, nameStatusEntry{kind: ChangeModified, path: filepath.ToSlash(tokens[i+1])})
			i += 2
		default:
			// Unknown status codes are treated as modifications so the file is
			// still scanned rather than silently dropped.
			if i+1 >= len(tokens) {
				return entries
			}
			logging.Warn().Str("status", status).Str("path", tokens[i+1]).Msg("unknown git change status, treating as modified")
			entries = append(entries, nameStatusEntry{kind: ChangeModified, path: filepath.ToSlash(tokens[i+1])})
			i += 2
		}
	}

	return entries
}

// mergeChange folds a change into the accumulated map. A later deletion wins
// over an earlier addition/modification; renames preserve the old path when
// the file was not otherwise seen.
func mergeChange(byPath map[string]FileChange, change FileChange) {
	existing, ok := byPath[change.Path]
	if !ok {
		byPath[change.Path] = change
		return
	}

	if change.Kind == ChangeDeleted {
		byPath[change.Path] = change
		return
	}
	if existing.Kind == ChangeDeleted {
		// Re-added after a deletion within the union of ranges.
		existing.Kind = change.Kind
	}
	if change.OldPath != "" && existing.OldPath == "" {
		existing.OldPath = change.OldPath
	}
	if existing.Kind == ChangeAdded || change.Kind == ChangeRenamed {
		existing.Kind = change.Kind
	}
	byPath[change.Path] = existing
}

// sortedChanges returns the changes ordered by path for deterministic output.
func sortedChanges(byPath map[string]FileChange) []FileChange {
	changes := make([]FileChange, 0, len(byPath))
	for _, change := range byPath {
		changes = append(changes, change)
	}
	sort.Slice(changes, func(i, j int) bool {
		return changes[i].Path < changes[j].Path
	})
	return changes
}

// Scannable returns the subset of changes that have a post-image to scan.
// Deleted files are excluded since they no longer exist.
func (c *Changeset) Scannable() []FileChange {
	if c == nil {
		return nil
	}
	scannable := make([]FileChange, 0, len(c.Files))
	for _, change := range c.Files {
		if change.Kind != ChangeDeleted {
			scannable = append(scannable, change)
		}
	}
	return scannable
}

// RenameAliases maps a new path to the old path it was renamed from. The map
// is used to keep baselines and .gitleaksignore fingerprints working across
// renames.
func (c *Changeset) RenameAliases() map[string]string {
	aliases := make(map[string]string)
	for _, change := range c.Files {
		if change.Kind == ChangeRenamed && change.OldPath != "" {
			aliases[change.Path] = change.OldPath
		}
	}
	return aliases
}
