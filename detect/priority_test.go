package detect

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

// loadConfigForPriority reads a fixture using a private Viper instance so
// these tests do not depend on global Viper state.
func loadConfigForPriority(t *testing.T, name string) config.Config {
	t.Helper()
	data, err := os.ReadFile(configPath + name)
	require.NoError(t, err)

	v := viper.New()
	v.SetConfigType("toml")
	require.NoError(t, v.ReadConfig(strings.NewReader(string(data))))

	vc := &config.ViperConfig{}
	require.NoError(t, v.Unmarshal(vc))
	cfg, err := vc.Translate()
	require.NoError(t, err)
	return cfg
}

// 形态 3: 多条规则命中同一位置时按声明优先级只出一条结论，败者作为佐证
// 保留，且优先级来源可追溯。
func TestPriorityExplicitWinsAndEvidence(t *testing.T) {
	cfg := loadConfigForPriority(t, "priority.toml")
	d := NewDetector(cfg)

	findings := d.DetectString("token = \"token-1234567890\"")
	require.Len(t, findings, 1, "same-location matches must collapse to one conclusion")

	winner := findings[0]
	assert.Equal(t, "high-priority", winner.RuleID, "the highest-priority rule wins despite later declaration")
	assert.Equal(t, 10, winner.RulePriority)
	require.NotEmpty(t, winner.RulePrioritySource, "priority provenance must be traceable")

	// The two losing rules survive as supporting evidence, not as
	// independent findings.
	var loserIDs []string
	for _, s := range winner.SupportingFindings {
		loserIDs = append(loserIDs, s.RuleID)
	}
	assert.ElementsMatch(t, []string{"low-priority", "no-priority"}, loserIDs)
}

// 形态 3 (tie-breaking): 无人声明优先级时，声明顺序决定赢家，结果确定。
func TestPriorityDefaultsToDeclarationOrder(t *testing.T) {
	cfg := loadConfigForPriority(t, "priority_default_order.toml")
	d := NewDetector(cfg)

	// Repeat to prove determinism; map iteration can otherwise reshuffle.
	for i := 0; i < 20; i++ {
		findings := d.DetectString("token = \"token-1234567890\"")
		require.Len(t, findings, 1)
		assert.Equal(t, "first-declared", findings[0].RuleID)
		assert.Empty(t, findings[0].RulePrioritySource)
		assert.Len(t, findings[0].SupportingFindings, 1)
		assert.Equal(t, "second-declared", findings[0].SupportingFindings[0].RuleID)
	}
}

// 硬约束 4 (throughput): distinct locations stay separate findings even
// though each location has its own collision. The priority pass never
// merges across positions, and single-match output gains no supporting
// entries (preserving byte-identical behavior for the common case).
func TestPriorityDistinctLocationsUnaffected(t *testing.T) {
	cfg := loadConfigForPriority(t, "priority.toml")
	d := NewDetector(cfg)

	findings := d.DetectString("a = \"token-1111111111\"\nb = \"token-2222222222\"")
	require.Len(t, findings, 2, "the two distinct positions must not be merged into one")

	// Each location independently resolves its own three-way collision.
	lines := map[int]bool{}
	for _, f := range findings {
		assert.Len(t, f.SupportingFindings, 2, "each position keeps its own two losers as evidence")
		lines[f.StartLine] = true
	}
	assert.Len(t, lines, 2, "findings retain their distinct locations")
}

// Ensure SupportingFinding carries its own rule's priority provenance.
func TestPrioritySupportingEvidenceProvenance(t *testing.T) {
	cfg := loadConfigForPriority(t, "priority.toml")
	d := NewDetector(cfg)

	findings := d.DetectString("token = \"token-1234567890\"")
	require.Len(t, findings, 1)

	byRule := map[string]*report.SupportingFinding{}
	for _, s := range findings[0].SupportingFindings {
		byRule[s.RuleID] = s
	}
	low, ok := byRule["low-priority"]
	require.True(t, ok)
	assert.Equal(t, 1, low.RulePriority)
}
