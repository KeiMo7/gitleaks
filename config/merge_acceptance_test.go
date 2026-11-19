package config

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

const mergeFixtureDir = "../testdata/config/merge/"

// loadMergeFixture reads and translates a fixture using a private Viper
// instance, so tests can run concurrently without touching global state.
func loadMergeFixture(t *testing.T, name string) (Config, error) {
	t.Helper()
	return readMergeFixture(name)
}

// readMergeFixture is safe to call from multiple goroutines: it allocates
// a fresh Viper instance per call and never touches package-level state.
func readMergeFixture(name string) (Config, error) {
	path := filepath.Join(mergeFixtureDir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	v := viper.New()
	v.SetConfigType("toml")
	if err := v.ReadConfig(strings.NewReader(string(data))); err != nil {
		return Config{}, err
	}
	vc := &ViperConfig{}
	if err := v.Unmarshal(vc); err != nil {
		return Config{}, err
	}
	vc.configPath = path
	return vc.Translate()
}

func mustLoadMergeFixture(t *testing.T, name string) Config {
	t.Helper()
	cfg, err := loadMergeFixture(t, name)
	require.NoError(t, err)
	return cfg
}

// mergeComparer ignores unexported bookkeeping and compares regexes by
// their source pattern.
var mergeComparer = cmp.Options{
	cmp.Comparer(func(x, y *regexp.Regexp) bool {
		if x == nil || y == nil {
			return x == y
		}
		return x.String() == y.String()
	}),
	cmpopts.IgnoreUnexported(Rule{}, Allowlist{}),
}

// 形态 1 + 硬约束 1: 差异项覆盖继承条件，显式零值可关闭判定，且与未声明不同。
func TestMergeOverrideAndExplicitZero(t *testing.T) {
	cfg := mustLoadMergeFixture(t, "child_override.toml")

	alpha := cfg.Rules["alpha"]
	// entropy was explicitly reset to 0 in the child.
	assert.Equal(t, 0.0, alpha.Entropy, "explicit entropy=0 must disable entropy, not inherit 2.0")
	// regex is inherited because the child never declared it.
	require.NotNil(t, alpha.Regex)
	assert.Equal(t, `alpha-[0-9]+`, alpha.Regex.String())
	// tags were explicitly declared, so they replace the inherited set.
	assert.Equal(t, []string{"t9"}, alpha.Tags)
	// a brand-new local rule is present and ordered after inherited ones.
	assert.Contains(t, cfg.OrderedRules, "delta")
}

// 硬约束 1 (explicit): 显式空切片清空，未声明保持继承 —— 两者必须不同。
func TestMergeExplicitResetDiffersFromUndeclared(t *testing.T) {
	reset := mustLoadMergeFixture(t, "child_reset.toml")
	override := mustLoadMergeFixture(t, "child_override.toml")

	resetAlpha := reset.Rules["alpha"]
	overrideAlpha := override.Rules["alpha"]

	// child_reset declares tags=[] and keywords=[] explicitly.
	assert.Equal(t, []string{}, resetAlpha.Tags, "explicit empty tags must clear the inherited tags")
	assert.Equal(t, []string{}, resetAlpha.Keywords, "explicit empty keywords must clear inherited keywords")

	// child_override declares tags=["t9"] (replace) but never mentions
	// keywords, so the inherited keyword survives.
	assert.Equal(t, []string{"t9"}, overrideAlpha.Tags)
	assert.Equal(t, []string{"alpha"}, overrideAlpha.Keywords, "undeclared keywords must be inherited")

	// And the two configurations must observably differ.
	assert.NotEqual(t, resetAlpha.Tags, overrideAlpha.Tags)
}

// 形态 2 + 验收 3: 同一标识重复声明在加载阶段被拒绝。
func TestMergeDuplicateIDRejected(t *testing.T) {
	_, err := loadMergeFixture(t, "duplicate_id.toml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate rule ID 'dup'")
}

// 形态 4: 放行清单条目级合并 —— 可新增、可禁用单条且不影响其他条目。
func TestMergeAllowlistEntryLevel(t *testing.T) {
	cfg := mustLoadMergeFixture(t, "child_allowlist.toml")

	// The inherited "global-node" entry was disabled; "global-mock" stays,
	// and the new "global-test" entry is added.
	var globalIDs []string
	for _, a := range cfg.Allowlists {
		globalIDs = append(globalIDs, a.ID)
	}
	assert.ElementsMatch(t, []string{"global-mock", "global-test"}, globalIDs)

	alpha := cfg.Rules["alpha"]
	var ruleIDs []string
	for _, a := range alpha.Allowlists {
		ruleIDs = append(ruleIDs, a.ID)
	}
	// "alpha-stop" disabled, "alpha-path" added.
	assert.ElementsMatch(t, []string{"alpha-path"}, ruleIDs)

	// An unrelated rule's allowlists are untouched.
	beta := cfg.Rules["beta"]
	assert.Nil(t, beta.Allowlists)
}

// 形态 5: 标签/关键词去重，重复继承不会让列表膨胀。
func TestMergeMetadataDedup(t *testing.T) {
	cfg := mustLoadMergeFixture(t, "metadata_dedup.toml")
	rule := cfg.Rules["dup-tags"]

	// Duplicate tags collapse while preserving first-seen order.
	assert.Equal(t, []string{"a", "b", "c"}, rule.Tags)
	// Keywords are lower-cased and de-duplicated.
	assert.Equal(t, []string{"dup", "other"}, rule.Keywords)
	// The global keyword set holds each keyword exactly once.
	assert.Len(t, cfg.Keywords, 2)
}

// 形态 6: 书写顺序成为可观察的稳定顺序。
func TestMergeStableDeclarationOrder(t *testing.T) {
	cfg := mustLoadMergeFixture(t, "base.toml")
	assert.Equal(t, []string{"alpha", "beta", "gamma"}, cfg.OrderedRules)

	// Determinism: load repeatedly and confirm identical order every time.
	for i := 0; i < 10; i++ {
		again := mustLoadMergeFixture(t, "base.toml")
		assert.Equal(t, cfg.OrderedRules, again.OrderedRules)
	}
}

// 形态 7: 空配置、只含放行的配置、继承成环各有明确且不同的结果。
func TestMergeEmptyAllowlistOnlyAndCycle(t *testing.T) {
	// Empty config: no rules, no allowlists, no error.
	empty := mustLoadMergeFixture(t, "empty.toml")
	assert.Empty(t, empty.Rules)
	assert.Empty(t, empty.OrderedRules)
	assert.Nil(t, empty.Allowlists)

	// Allowlist-only config: no rules but one allowlist.
	only := mustLoadMergeFixture(t, "only_allowlist.toml")
	assert.Empty(t, only.Rules)
	require.Len(t, only.Allowlists, 1)
	assert.Equal(t, "sole-entry", only.Allowlists[0].ID)

	// Two-node cycle fails at load time with a cycle-specific error.
	_, err := loadMergeFixture(t, "cyc_a.toml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "inheritance cycle")

	// Self cycle is detected too.
	_, err = loadMergeFixture(t, "self_cycle.toml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "inheritance cycle")
}

// 形态 8: 导出物再加载得到完全相同的规则集。
func TestMergeExportRoundTrip(t *testing.T) {
	original := mustLoadMergeFixture(t, "child_allowlist.toml")

	exported, err := original.ExportTOML()
	require.NoError(t, err)
	require.NotContains(t, string(exported), "[extend]")

	v := viper.New()
	v.SetConfigType("toml")
	require.NoError(t, v.ReadConfig(strings.NewReader(string(exported))))
	reloadedVC := &ViperConfig{}
	require.NoError(t, v.Unmarshal(reloadedVC))
	reloaded, err := reloadedVC.Translate()
	require.NoError(t, err)

	// Same declaration order.
	assert.Equal(t, original.OrderedRules, reloaded.OrderedRules)

	// Rule sets are equivalent (regex source compared, internal fields
	// ignored). The export is a standalone document, so the [extend]
	// provenance and source path are intentionally not part of the
	// round-trip contract; rule content and order must match exactly.
	if diff := cmp.Diff(
		exportComparable(original),
		exportComparable(reloaded),
		mergeComparer,
		cmp.AllowUnexported(Rule{}, Allowlist{}),
		cmpopts.IgnoreFields(Config{}, "Extend", "Path"),
	); diff != "" {
		t.Fatalf("round-trip mismatch (-want +got):\n%s", diff)
	}

	// Global allowlists round-trip too.
	assert.Len(t, reloaded.Allowlists, len(original.Allowlists))
}

// exportComparable strips the non-round-trippable provenance field.
func exportComparable(c Config) Config {
	rules := make(map[string]Rule, len(c.Rules))
	for id, r := range c.Rules {
		r.PrioritySource = ""
		rules[id] = r
	}
	c.Rules = rules
	return c
}

// 失败降级 1: 继承链超深给出明确错误，而不是静默截断。
func TestMergeDepthLimit(t *testing.T) {
	_, err := loadMergeFixture(t, "depth_0.toml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "inheritance depth exceeded")
}

// 失败降级 2: 上级配置不可读时整次加载失败。
func TestMergeUnreadableParentFails(t *testing.T) {
	_, err := loadMergeFixture(t, "bad_parent.toml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load extended config")
}

// 失败降级 3: 单条规则非法（无 regex 无 path）中止且不产生半成品。
func TestMergeInvalidRuleAborts(t *testing.T) {
	_, err := loadMergeFixture(t, "invalid_rule.toml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "both |regex| and |path| are empty")
}

// 失败降级 4 + 硬约束 4: 悬空引用在加载阶段失败并指出目标。
func TestMergeDanglingReferences(t *testing.T) {
	_, err := loadMergeFixture(t, "dangling_required.toml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "'missing-rule'")

	_, err = loadMergeFixture(t, "dangling_target.toml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "target rule ID 'ghost-rule'")

	_, err = loadMergeFixture(t, "dangling_disabled.toml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "'never-declared'")
}

// 硬约束 3: 合并不修改被继承的上游配置。
func TestMergeDoesNotMutateParent(t *testing.T) {
	base := mustLoadMergeFixture(t, "base.toml")
	baseAlphaTags := append([]string(nil), base.Rules["alpha"].Tags...)
	baseAlphaEntropy := base.Rules["alpha"].Entropy

	_ = mustLoadMergeFixture(t, "child_override.toml")
	_ = mustLoadMergeFixture(t, "child_reset.toml")

	again := mustLoadMergeFixture(t, "base.toml")
	assert.Equal(t, baseAlphaTags, again.Rules["alpha"].Tags)
	assert.Equal(t, baseAlphaEntropy, again.Rules["alpha"].Entropy)
}

// 硬约束 5: 并发加载多份配置互不干扰。
func TestMergeConcurrentLoads(t *testing.T) {
	fixtures := []string{
		"base.toml", "child_override.toml", "child_reset.toml",
		"child_allowlist.toml", "empty.toml", "only_allowlist.toml",
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(fixtures)*5)
	for round := 0; round < 5; round++ {
		for _, f := range fixtures {
			wg.Add(1)
			go func(name string) {
				defer wg.Done()
				cfg, err := readMergeFixture(name)
				if err != nil {
					errs <- err
					return
				}
				// Re-export inside the goroutine to also exercise
				// allocation paths under concurrency.
				if _, err := cfg.ExportTOML(); err != nil {
					errs <- err
				}
			}(f)
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent load failed: %v", err)
	}
}
