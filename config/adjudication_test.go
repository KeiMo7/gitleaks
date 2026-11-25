package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadAdjudicationConfig translates a fixture TOML. extend.path is resolved
// relative to the process working directory, so the working directory is
// switched to the fixture directory for the duration of the call and restored
// before returning (each test is therefore self-contained).
func loadAdjudicationConfig(t *testing.T, name string) Config {
	t.Helper()
	dir := filepath.Join("..", "testdata", "config", "valid", "adjudication")
	wd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	restore := func() {
		_ = os.Chdir(wd)
		extendDepth = 0
		viper.Reset()
	}
	defer restore()

	viper.SetConfigFile(name)
	require.NoError(t, viper.ReadInConfig())
	var vc ViperConfig
	require.NoError(t, viper.Unmarshal(&vc))
	cfg, err := vc.Translate()
	require.NoError(t, err)
	return cfg
}

// TestAllowlistStampsProvenance verifies the four-layer provenance, stable IDs
// and declaration-order positions are attached and recoverable.
func TestAllowlistStampsProvenance(t *testing.T) {
	cfg := loadAdjudicationConfig(t, "stamp_layered.toml")

	// Global list set: only untargeted allowlists.
	var globalLayers, globalIDs []string
	for _, al := range cfg.Allowlists {
		require.NotNil(t, al.Stamp)
		globalLayers = append(globalLayers, al.Stamp.Layer.String())
		globalIDs = append(globalIDs, al.Stamp.ID)
	}
	assert.ElementsMatch(t, []string{"extension", "global"}, globalLayers)

	// Every ID is unique and matches the AL-NNNN stable format.
	seen := map[string]struct{}{}
	for _, id := range globalIDs {
		assert.Regexp(t, `^AL-\d{4}$`, id)
		_, dup := seen[id]
		assert.False(t, dup, "duplicate allowlist ID: %s", id)
		seen[id] = struct{}{}
	}

	// Provenance layers across the whole inventory: rule-owned blocks are
	// layer=rule (even when declared in an extension file), untargeted global
	// blocks keep their file provenance (global vs extension), and both
	// scopes are represented.
	inventory := cfg.allowlistInventory()
	var allLayers, allScopes, allFiles []string
	for _, al := range inventory {
		require.NotNil(t, al.Stamp)
		allLayers = append(allLayers, al.Stamp.Layer.String())
		allScopes = append(allScopes, al.Stamp.Scope.String())
		allFiles = append(allFiles, al.Stamp.ConfigPath)
	}
	assert.Contains(t, allLayers, "rule")
	assert.Contains(t, allLayers, "global")
	assert.Contains(t, allLayers, "extension")
	assert.Contains(t, allScopes, "global")
	assert.Contains(t, allScopes, "targeted")
	assert.Contains(t, allFiles, "stamp_layered.toml")
	assert.Contains(t, allFiles, "stamp_base.toml")

	// The extension rule carries a rule-layer block even though it was
	// declared inside the extension config file.
	extRule := cfg.Rules["stamp-extension-rule"]
	var extRuleLayers []string
	for _, al := range extRule.Allowlists {
		require.NotNil(t, al.Stamp)
		extRuleLayers = append(extRuleLayers, al.Stamp.Layer.String())
	}
	assert.Contains(t, extRuleLayers, "rule")

	// Rule-layer allowlists include the rule's own block (layer=rule) plus
	// the top-config targeted declaration (layer=global, scope=targeted).
	rule := cfg.Rules["stamp-rule"]
	var (
		ruleScopes   []string
		ruleLayers   []string
		ruleOrdinals []int
	)
	for _, al := range rule.Allowlists {
		require.NotNil(t, al.Stamp)
		ruleScopes = append(ruleScopes, al.Stamp.Scope.String())
		ruleLayers = append(ruleLayers, al.Stamp.Layer.String())
		ruleOrdinals = append(ruleOrdinals, al.Stamp.Ordinal)
		assert.NotEmpty(t, al.Stamp.ConfigPath)
	}
	assert.Contains(t, ruleScopes, "targeted")
	assert.Contains(t, ruleLayers, "rule")
	assert.Contains(t, ruleLayers, "global")

	// Ordinals are strictly increasing in declaration order.
	for i := 1; i < len(ruleOrdinals); i++ {
		assert.Greater(t, ruleOrdinals[i], ruleOrdinals[i-1])
	}

	// Legacy folding is represented with kind=allowlist.
	var kinds []string
	for _, al := range cfg.allowlistInventory() {
		kinds = append(kinds, al.Stamp.Kind)
	}
	assert.Contains(t, kinds, "allowlists")
}

// TestAllowlistStampsDeterministic verifies two translations assign identical
// IDs to the same declaration positions.
func TestAllowlistStampsDeterministic(t *testing.T) {
	first := loadAdjudicationConfig(t, "stamp_layered.toml")
	second := loadAdjudicationConfig(t, "stamp_layered.toml")

	firstIDs := inventoryIDs(first)
	secondIDs := inventoryIDs(second)
	assert.Equal(t, firstIDs, secondIDs)
}

func inventoryIDs(cfg Config) []string {
	var ids []string
	for _, al := range cfg.allowlistInventory() {
		if al.Stamp != nil {
			ids = append(ids, al.Stamp.ID)
		}
	}
	return ids
}

// TestCrossSourceDuplicateConflict verifies synonymous allowlists in different
// sources produce a stable conflict code and both allowlist identities.
func TestCrossSourceDuplicateConflict(t *testing.T) {
	cfg := loadAdjudicationConfig(t, "duplicate_top.toml")
	conflicts := cfg.AllowlistConflicts()

	var dup *AllowlistConflict
	for i := range conflicts {
		if conflicts[i].Code == ConflictDuplicate {
			dup = &conflicts[i]
			break
		}
	}
	require.NotNil(t, dup, "expected a cross-source duplicate conflict")
	assert.Len(t, dup.AllowlistIDs, 2)
	assert.ElementsMatch(t, []string{"extension", "global"}, dup.Layers)

	// Determinism: a second translation yields the same conflict.
	cfg2 := loadAdjudicationConfig(t, "duplicate_top.toml")
	dup2 := func() *AllowlistConflict {
		for _, c := range cfg2.AllowlistConflicts() {
			if c.Code == ConflictDuplicate {
				return &c
			}
		}
		return nil
	}()
	require.NotNil(t, dup2)
	assert.Equal(t, dup.AllowlistIDs, dup2.AllowlistIDs)
}

// TestSameSourceDuplicateNotConflict verifies duplicates within one source are
// not flagged as cross-source conflicts.
func TestSameSourceDuplicateNotConflict(t *testing.T) {
	cfg := loadAdjudicationConfig(t, "stamp_layered.toml")
	for _, c := range cfg.AllowlistConflicts() {
		assert.NotEqual(t, ConflictDuplicate, c.Code)
	}
}

// TestEmptyAllowlistRejectedAtLoad verifies an empty allowlist fails at load
// time with a stable code, entry number and source, while the legacy message
// text is preserved.
func TestEmptyAllowlistRejectedAtLoad(t *testing.T) {
	t.Cleanup(func() {
		extendDepth = 0
		viper.Reset()
	})
	path := filepath.Join("..", "testdata", "config", "invalid", "allowlist_rule_empty.toml")
	viper.SetConfigFile(path)
	require.NoError(t, viper.ReadInConfig())
	var vc ViperConfig
	require.NoError(t, viper.Unmarshal(&vc))
	_, err := vc.Translate()
	require.Error(t, err)

	var le *AllowlistLoadError
	require.ErrorAs(t, err, &le)
	assert.Equal(t, LoadCodeEmptyAllowlist, le.Code)
	assert.Equal(t, 0, le.EntryIndex, "first entry is index zero")
	assert.Equal(t, "example", le.RuleID)
	assert.Contains(t, le.Location(), "allowlist_rule_empty.toml")
	// The legacy message stays intact.
	assert.EqualError(t, err,
		"example: [[rules.allowlists]] must contain at least one check for: commits, paths, regexes, or stopwords")
}

// TestUnknownTargetRuleConflict verifies the unknown-target-rule path fails
// hard with a stable code, the involved allowlist identities and a preserved
// legacy error message.
func TestUnknownTargetRuleConflict(t *testing.T) {
	t.Cleanup(func() {
		extendDepth = 0
		viper.Reset()
	})
	path := filepath.Join("..", "testdata", "config", "invalid", "allowlist_global_target_rule_id.toml")
	viper.SetConfigFile(path)
	require.NoError(t, viper.ReadInConfig())
	var vc ViperConfig
	require.NoError(t, viper.Unmarshal(&vc))
	_, err := vc.Translate()
	require.Error(t, err)
	assert.EqualError(t, err, "[[allowlists]] target rule ID 'github-pat' does not exist")

	var unknown *UnknownTargetRuleError
	require.ErrorAs(t, err, &unknown)
	assert.Equal(t, ConflictUnknownRule, unknown.Code)
	assert.Equal(t, "github-pat", unknown.TargetRuleID)
	assert.NotEmpty(t, unknown.AllowlistIDs)
	assert.Contains(t, unknown.Location(), "github-pat")
}
