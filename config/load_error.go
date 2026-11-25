package config

import (
	"errors"
	"fmt"
)

// AllowlistLoadError wraps a load-time allowlist failure with a stable code,
// the declaration position (which entry, which source) and, when available,
// the stable allowlist identity. It never carries scanned content. The
// rendered message is kept byte-identical to the underlying error so existing
// error-string contracts and golden assertions are unchanged; callers use
// errors.As to read the structured fields.
type AllowlistLoadError struct {
	// Code is one of the LoadCode* constants.
	Code string
	// EntryIndex is the zero-based allowlist table index in the declaring file.
	EntryIndex int
	// Kind is "allowlists" or the legacy "allowlist".
	Kind string
	// ConfigPath is the declaring configuration file ("<default>" for builtin).
	ConfigPath string
	// RuleID is the owning rule for rule-layer declarations, empty otherwise.
	RuleID string
	// AllowlistID is populated when a stamp had already been assigned.
	AllowlistID string
	// Err is the underlying error whose message is preserved for compatibility.
	Err error
}

func (e *AllowlistLoadError) Error() string {
	return e.Err.Error()
}

func (e *AllowlistLoadError) Unwrap() error {
	return e.Err
}

// Is enables errors.Is checks against the wrapped sentinel.
func (e *AllowlistLoadError) Is(target error) bool {
	return target == e.Err
}

// Location returns a human-pointable, content-free declaration location.
func (e *AllowlistLoadError) Location() string {
	loc := e.ConfigPath
	if e.RuleID != "" {
		loc = fmt.Sprintf("%s (rule %s)", loc, e.RuleID)
	}
	return fmt.Sprintf("%s %s entry #%d", loc, e.Kind, e.EntryIndex+1)
}

// loadCodeFor maps a parse/validation error to its stable load code.
func loadCodeFor(err error) string {
	if errors.Is(err, ErrEmptyAllowlist) {
		return LoadCodeEmptyAllowlist
	}
	return "AL-LOAD-INVALID-DECLARATION"
}
