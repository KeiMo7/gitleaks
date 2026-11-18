package config

import (
	"fmt"
	"sort"
	"strings"
)

// Level is the shared, ordered representation used by both rule severity and
// confidence. The zero value (LevelUnknown) is never assigned to a rule:
// rules without an explicit annotation get LevelHigh so that the default
// behavior stays backwards-compatible (every hit is still blocking).
type Level int

const (
	LevelUnknown Level = iota
	LevelLow
	LevelMedium
	LevelHigh
	LevelCritical
)

// Severity levels, ordered from least to most severe.
const (
	SeverityLow      = LevelLow
	SeverityMedium   = LevelMedium
	SeverityHigh     = LevelHigh
	SeverityCritical = LevelCritical
)

// Confidence levels, ordered from least to most confident. Confidence does
// not use "critical".
const (
	ConfidenceLow    = LevelLow
	ConfidenceMedium = LevelMedium
	ConfidenceHigh   = LevelHigh
)

// DefaultSeverity and DefaultConfidence define the conservative semantics for
// rules that do not carry an explicit level annotation: an unannotated rule is
// treated as high severity / high confidence, i.e. the same blocking behavior
// gitleaks had before level-based gating existed.
const (
	DefaultSeverity   = SeverityHigh
	DefaultConfidence = ConfidenceHigh
)

var levelNames = map[Level]string{
	LevelLow:      "low",
	LevelMedium:   "medium",
	LevelHigh:     "high",
	LevelCritical: "critical",
}

// String returns the canonical lowercase name of the level.
func (l Level) String() string {
	if name, ok := levelNames[l]; ok {
		return name
	}
	return "unknown"
}

// MarshalText serializes the level using its canonical lowercase name.
func (l Level) MarshalText() ([]byte, error) {
	return []byte(l.String()), nil
}

// UnmarshalText parses a level name case-insensitively. Unknown names resolve
// to LevelUnknown so callers can apply a conservative fallback instead of
// silently downgrading the rule.
func (l *Level) UnmarshalText(text []byte) error {
	parsed, err := ParseLevel(string(text))
	if err != nil {
		*l = LevelUnknown
		return err
	}
	*l = parsed
	return nil
}

// ParseLevel parses a case-insensitive level name ("low", "medium", "high",
// "critical") and returns an error listing the valid range for any other
// value.
func ParseLevel(raw string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "low":
		return LevelLow, nil
	case "medium":
		return LevelMedium, nil
	case "high":
		return LevelHigh, nil
	case "critical":
		return LevelCritical, nil
	default:
		return LevelUnknown, fmt.Errorf("unknown level %q: valid values are %s", raw, strings.Join(ValidLevelNames(), ", "))
	}
}

// ValidLevelNames returns the accepted level names in ascending order.
func ValidLevelNames() []string {
	names := make([]string, 0, len(levelNames))
	for _, name := range levelNames {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ValidSeverityNames returns the accepted severity names in ascending order.
func ValidSeverityNames() []string {
	return []string{"critical", "high", "low", "medium"}
}

// ValidConfidenceNames returns the accepted confidence names in ascending
// order.
func ValidConfidenceNames() []string {
	return []string{"high", "low", "medium"}
}
