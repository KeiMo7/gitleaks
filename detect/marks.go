package detect

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// MarkStatus enumerates the lifecycle of a false-positive mark.
type MarkStatus string

const (
	// MarkSuppressed means the fingerprint is a confirmed false positive and
	// matching findings must be suppressed.
	MarkSuppressed MarkStatus = "suppressed"
	// MarkRevoked means a previous suppression was explicitly undone; the
	// finding must be reported again. Keeping the revoked entry (instead of
	// deleting it) makes the decision auditable and prevents a stale mark
	// from being silently re-added.
	MarkRevoked MarkStatus = "revoked"
)

// Mark is a single, revocable false-positive decision. It references a
// finding solely by its fingerprint, so no secret material is ever stored.
type Mark struct {
	// Fingerprint is the finding fingerprint (file:rule:line or
	// commit:file:rule:line).
	Fingerprint string `json:"fingerprint"`
	// Status is "suppressed" or "revoked".
	Status MarkStatus `json:"status"`
	// Note is optional human context. It never contains secret material by
	// contract; only fingerprints are matched on.
	Note string `json:"note,omitempty"`
}

// MarksFile is the on-disk representation.
type MarksFile struct {
	// SchemaVersion guards future format changes.
	SchemaVersion int    `json:"schema_version"`
	Marks         []Mark `json:"marks"`
}

const marksSchemaVersion = 1

var (
	// ErrMarkNotFound is returned when revoking/querying an unknown mark.
	ErrMarkNotFound = errors.New("mark not found")
	// ErrInvalidMark is returned for malformed input.
	ErrInvalidMark = errors.New("invalid mark")
)

// MarksStore is a persistent, revocable false-positive store. All operations
// are deterministic and keyed by finding fingerprint.
type MarksStore struct {
	path  string
	marks map[string]Mark
}

// NewMarksStore opens (or lazily creates) a marks store at path. A missing
// file is normal and yields an empty store rather than an error.
func NewMarksStore(path string) (*MarksStore, error) {
	store := &MarksStore{path: path, marks: make(map[string]Mark)}
	if path == "" {
		return store, nil
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, fmt.Errorf("cannot read marks file %s: %w", path, err)
	}

	var file MarksFile
	if err := json.Unmarshal(bytes, &file); err != nil {
		return nil, fmt.Errorf("cannot parse marks file %s: %w", path, err)
	}
	if file.SchemaVersion != marksSchemaVersion {
		return nil, fmt.Errorf("marks file %s schema_version %d is not supported (this build supports %d)",
			path, file.SchemaVersion, marksSchemaVersion)
	}
	for _, m := range file.Marks {
		if m.Fingerprint == "" || (m.Status != MarkSuppressed && m.Status != MarkRevoked) {
			return nil, fmt.Errorf("%w: %+v", ErrInvalidMark, m)
		}
		store.marks[m.Fingerprint] = m
	}
	return store, nil
}

// Suppress records (or re-asserts) a suppressed fingerprint. A previously
// revoked fingerprint is moved back to suppressed.
func (s *MarksStore) Suppress(fingerprint, note string) error {
	if fingerprint == "" {
		return ErrInvalidMark
	}
	s.marks[fingerprint] = Mark{Fingerprint: fingerprint, Status: MarkSuppressed, Note: note}
	return s.persist()
}

// Revoke undoes a suppression. The fingerprint is retained with status
// "revoked" so the history is preserved.
func (s *MarksStore) Revoke(fingerprint string) error {
	if fingerprint == "" {
		return ErrInvalidMark
	}
	existing, ok := s.marks[fingerprint]
	if !ok {
		return fmt.Errorf("%w: %s", ErrMarkNotFound, fingerprint)
	}
	existing.Status = MarkRevoked
	s.marks[fingerprint] = existing
	return s.persist()
}

// IsSuppressed reports whether the fingerprint currently suppresses findings.
func (s *MarksStore) IsSuppressed(fingerprint string) bool {
	m, ok := s.marks[fingerprint]
	return ok && m.Status == MarkSuppressed
}

// IsRevoked reports whether a suppression was explicitly undone.
func (s *MarksStore) IsRevoked(fingerprint string) bool {
	m, ok := s.marks[fingerprint]
	return ok && m.Status == MarkRevoked
}

// List returns all marks in a stable, fingerprint-sorted order.
func (s *MarksStore) List() []Mark {
	out := make([]Mark, 0, len(s.marks))
	for _, m := range s.marks {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out
}

// persist writes the store atomically (temp file + rename) so a crash cannot
// leave a half-written marks file behind.
func (s *MarksStore) persist() error {
	if s.path == "" {
		// In-memory only (e.g. library usage with no path configured).
		return nil
	}

	file := MarksFile{SchemaVersion: marksSchemaVersion, Marks: s.List()}
	bytes, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode marks file: %w", err)
	}

	dir := filepath.Dir(s.path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("cannot create marks directory: %w", err)
		}
	}
	tmp, err := os.CreateTemp(dir, ".gitleaks-marks-*.tmp")
	if err != nil {
		return fmt.Errorf("cannot create temp marks file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(bytes); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("cannot write marks file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cannot close marks file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("cannot finalize marks file: %w", err)
	}
	return nil
}
