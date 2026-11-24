package detect

import (
	"context"
	"fmt"
	"sync"

	"github.com/zricethezav/gitleaks/v8/lifecycle"
	"github.com/zricethezav/gitleaks/v8/report"
)

// Lifecycle collects a per-secret lifecycle view (first/last commit, current
// use, ref membership) alongside the normal scan.
//
// It is optional: when nil, behavior is byte-for-byte what it was before.
type Lifecycle struct {
	Spool  *lifecycle.Spool
	Hasher *lifecycle.Hasher

	// PathMap canonicalizes a path as seen in a commit (rename/move aware).
	// A nil mapper keeps paths unchanged.
	PathMap func(path string) string

	mu sync.Mutex

	scanErrors     int
	largeFragments int
}

// NoteScanError records a fragment that could not be scanned (unreadable
// object, timeout, corrupt data). The scan continues; the lifecycle report
// calls this out explicitly.
func (l *Lifecycle) NoteScanError() {
	l.mu.Lock()
	l.scanErrors++
	l.mu.Unlock()
}

// NoteLargeFragment records a fragment skipped for exceeding the configured
// size limit. The scan continues; the lifecycle report calls this out.
func (l *Lifecycle) NoteLargeFragment() {
	l.mu.Lock()
	l.largeFragments++
	l.mu.Unlock()
}

// Diagnostics returns the degradation counters accumulated during the scan.
func (l *Lifecycle) Diagnostics() (scanErrors, largeFragments int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.scanErrors, l.largeFragments
}

// Digest returns the lifecycle identity for a raw secret. Path-only rules
// have no captured secret, so their identity is the flagged path instead of a
// single shared "empty" digest.
func (l *Lifecycle) Digest(secret, path string) string {
	if secret == "" {
		return l.Hasher.Digest("path\x00" + path)
	}
	return l.Hasher.Digest(secret)
}

// Record adds a finding to the lifecycle spool. Suppressed findings never
// reach this method because suppression happens in AddFinding before the
// recorder is called.
func (l *Lifecycle) Record(f report.Finding, secretID string) error {
	if l == nil || l.Spool == nil {
		return nil
	}
	file := f.File
	if l.PathMap != nil {
		file = l.PathMap(file)
	}
	o := lifecycle.Occurrence{
		SecretID:    secretID,
		RuleID:      f.RuleID,
		Commit:      f.Commit,
		Date:        f.Date,
		File:        file,
		StartLine:   f.StartLine,
		EndLine:     f.EndLine,
		StartColumn: f.StartColumn,
		EndColumn:   f.EndColumn,
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.Spool.Add(o)
}

// TipScanner rescans the default branch tip with the same configuration.
//
// A fresh detector is built per blob so accumulated state (commit map, etc.)
// from the history scan cannot leak into the tip conclusion.
type TipScanner struct {
	NewDetector func() *Detector
	Hasher      *lifecycle.Hasher
	MaxBytes    int64
}

// ScanBlob implements lifecycle.TipScanFunc.
func (t *TipScanner) ScanBlob(ctx context.Context, path string, content []byte) ([]string, error) {
	d := t.NewDetector()
	if d == nil {
		return nil, fmt.Errorf("tip scanner has no detector factory")
	}
	// Identity must come from the raw value. Report redaction is a
	// presentation concern and would make every tip finding hash the same
	// redacted string, wrongly marking live secrets as removed.
	d.Redact = 0
	d.Lifecycle = nil
	if t.MaxBytes > 0 && int64(len(content)) > t.MaxBytes {
		return nil, nil
	}
	findings := d.DetectContext(ctx, Fragment{
		Raw:      string(content),
		FilePath: path,
	})
	ids := make([]string, 0, len(findings))
	seen := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		id := t.Hasher.Digest(f.Secret)
		if f.Secret == "" {
			id = t.Hasher.Digest("path\x00" + path)
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids, nil
}
