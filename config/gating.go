package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

// GatingConfig controls level-based pipeline blocking.
//
// The zero value means gating is disabled: every finding keeps the
// pre-gating behavior and any finding causes the configured non-zero exit
// code. This is what keeps upgrades backwards-compatible.
type GatingConfig struct {
	// Enabled is true only when the user explicitly opts into level gating
	// via [gating] in the config file or a command-line flag.
	Enabled bool

	// MinSeverity is the inclusive blocking severity threshold. A finding
	// blocks only when its rule severity is >= this level.
	MinSeverity Level

	// MinConfidence is the inclusive blocking confidence threshold. A finding
	// blocks only when its rule confidence is >= this level.
	MinConfidence Level

	// Exemptions suppress blocking for scoped rule/path combinations. An
	// exemption never hides a finding: exempted findings are still reported
	// and counted separately.
	Exemptions []*Exemption
}

// DefaultMinSeverity and DefaultMinConfidence are used when gating is enabled
// without an explicit threshold: only the lowest level reports without
// blocking, everything else blocks.
const (
	DefaultMinSeverity   = SeverityMedium
	DefaultMinConfidence = ConfidenceLow
)

// Exemption is a scoped, optionally time-bounded suppression of the blocking
// decision for a finding.
type Exemption struct {
	// Description explains why the exemption exists and is shown in the
	// gating summary when the exemption is applied.
	Description string

	// RuleID optionally limits the exemption to a single rule. Empty means
	// the exemption applies to any rule (path scoping still applies).
	RuleID string

	// Path is an optional regular expression matched against the finding
	// file path. Empty means the exemption is not path-scoped.
	Path string

	// pathRegexp is the compiled form of Path.
	pathRegexp *regexp.Regexp

	// ExpiresAt is an optional RFC3339 timestamp after which the exemption is
	// considered expired. Expired exemptions never suppress a finding and are
	// listed separately in the gating summary.
	ExpiresAt string

	// expiresAt is the parsed form of ExpiresAt.
	expiresAt *time.Time
}

// ViperGating is the viper-facing representation of [gating].
type ViperGating struct {
	MinSeverity   string
	MinConfidence string
	Exemptions    []*ViperExemption
}

// ViperExemption is the viper-facing representation of [[gating.exemptions]].
type ViperExemption struct {
	Description string
	RuleID      string `mapstructure:"ruleID"`
	Path        string
	ExpiresAt   string `mapstructure:"expiresAt"`
}

// ParseGating translates the viper representation into a validated
// GatingConfig. sectionPresent indicates whether the config file actually
// contains a [gating] table: an empty table still enables gating with the
// default thresholds, while a missing table keeps gating disabled.
func ParseGating(vg ViperGating, sectionPresent bool, knownRules map[string]Rule) (GatingConfig, error) {
	if !sectionPresent && vg.MinSeverity == "" && vg.MinConfidence == "" && len(vg.Exemptions) == 0 {
		return GatingConfig{}, nil
	}

	gating := GatingConfig{
		Enabled:       true,
		MinSeverity:   DefaultMinSeverity,
		MinConfidence: DefaultMinConfidence,
	}

	if vg.MinSeverity != "" {
		severity, err := ParseLevel(vg.MinSeverity)
		if err != nil {
			return GatingConfig{}, fmt.Errorf("invalid [gating] minSeverity: %w", err)
		}
		gating.MinSeverity = severity
	}

	if vg.MinConfidence != "" {
		confidence, err := ParseLevel(vg.MinConfidence)
		if err != nil {
			return GatingConfig{}, fmt.Errorf("invalid [gating] minConfidence: %w", err)
		}
		if confidence == LevelCritical {
			return GatingConfig{}, fmt.Errorf("invalid [gating] minConfidence %q: confidence has no critical level (valid values: %s)",
				vg.MinConfidence, strings.Join(ValidConfidenceNames(), ", "))
		}
		gating.MinConfidence = confidence
	}

	for index, ve := range vg.Exemptions {
		if ve == nil {
			continue
		}
		exemption := &Exemption{
			Description: ve.Description,
			RuleID:      ve.RuleID,
			Path:        ve.Path,
			ExpiresAt:   ve.ExpiresAt,
		}
		if strings.TrimSpace(ve.RuleID) == "" && strings.TrimSpace(ve.Path) == "" {
			return GatingConfig{}, fmt.Errorf("[[gating.exemptions]] entry #%d must scope at least one of ruleID or path, repository-wide exemptions are not allowed", index+1)
		}
		if ve.RuleID != "" {
			if _, ok := knownRules[ve.RuleID]; !ok {
				// Record the unknown rule but keep loading so the invalid
				// entry is surfaced in the gating summary instead of failing
				// the whole run. Mark it via RuleID matching logic below.
				exemption.RuleID = ve.RuleID
			}
		}
		if ve.Path != "" {
			exemption.pathRegexp = regexp.MustCompile(ve.Path)
		}
		if ve.ExpiresAt != "" {
			parsed, err := time.Parse(time.RFC3339, ve.ExpiresAt)
			if err != nil {
				return GatingConfig{}, fmt.Errorf("[[gating.exemptions]] entry #%d has an invalid expiresAt %q: use RFC3339, e.g. 2030-01-01T00:00:00Z",
					index+1, ve.ExpiresAt)
			}
			exemption.expiresAt = &parsed
		}
		gating.Exemptions = append(gating.Exemptions, exemption)
	}

	return gating, nil
}

// Matches reports whether the exemption applies to a finding identified by
// rule ID and file path.
func (e *Exemption) Matches(ruleID, path string) bool {
	if e == nil {
		return false
	}
	if e.RuleID != "" && e.RuleID != ruleID {
		return false
	}
	if e.pathRegexp != nil && !e.pathRegexp.MatchString(path) {
		return false
	}
	return true
}

// Expired reports whether the exemption has passed its expiry timestamp.
// Exemptions without an expiry never expire.
func (e *Exemption) Expired(now time.Time) bool {
	return e != nil && e.expiresAt != nil && now.After(*e.expiresAt)
}

// UnknownRule reports whether the exemption points at a rule that is not part
// of the loaded configuration.
func (e *Exemption) UnknownRule(knownRules map[string]Rule) bool {
	if e == nil || e.RuleID == "" {
		return false
	}
	_, ok := knownRules[e.RuleID]
	return !ok
}
