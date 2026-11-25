package config

import "fmt"

// UnknownTargetRuleError is returned when a targeted allowlist names a rule
// absent from the resolved configuration. It carries the stable conflict code
// and the identities of every allowlist involved, while its rendered message
// is preserved byte-for-byte for the legacy error-string contract.
type UnknownTargetRuleError struct {
	// Code is the stable conflict code (ConflictUnknownRule).
	Code string
	// TargetRuleID is the missing rule the allowlists point at.
	TargetRuleID string
	// AllowlistIDs are the stable identities of the offending allowlists.
	AllowlistIDs []string
	// Layers are their provenance layers (deduplicated).
	Layers []string
	// ConfigPaths are their declaring configuration files (deduplicated).
	ConfigPaths []string
}

func (e *UnknownTargetRuleError) Error() string {
	return fmt.Sprintf("[[allowlists]] target rule ID '%s' does not exist", e.TargetRuleID)
}

// Location returns a content-free description of the offending declarations.
func (e *UnknownTargetRuleError) Location() string {
	return fmt.Sprintf("target rule %q referenced by allowlists %v",
		e.TargetRuleID, e.AllowlistIDs)
}
