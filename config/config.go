package config

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	gv "github.com/hashicorp/go-version"
	"github.com/spf13/viper"

	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/version"
)

var (
	//go:embed gitleaks.toml
	DefaultConfig string
)

// ViperConfig is the config struct used by the Viper config package
// to parse the config file. This struct does not include regular expressions.
// It is used as an intermediary to convert the Viper config to the Config struct.
//
// Scalar rule fields use pointers so that an explicitly declared zero value
// can be distinguished from an undeclared field during inheritance merges.
// Slice fields use pointer-to-slice for the same reason: nil means
// undeclared while an empty non-nil slice means "explicitly reset".
type ViperConfig struct {
	Title       string
	Description string
	Extend      Extend
	Rules       []struct {
		ID          string
		Description *string
		Path        *string
		Regex       *string
		SecretGroup *int
		Entropy     *float64
		Keywords    *[]string
		Tags        *[]string
		SkipReport  *bool
		Priority    *int

		// Deprecated: this is a shim for backwards-compatibility.
		// TODO: Remove this in 9.x.
		AllowList *viperRuleAllowlist

		Allowlists []*viperRuleAllowlist
		Required   []*viperRequired
	}
	// Deprecated: this is a shim for backwards-compatibility.
	// TODO: Remove this in 9.x.
	AllowList *viperGlobalAllowlist

	Allowlists []*viperGlobalAllowlist

	MinVersion string

	configPath string
}

type viperRequired struct {
	ID            string
	WithinLines   *int `mapstructure:"withinLines"`
	WithinColumns *int `mapstructure:"withinColumns"`
}

type viperRuleAllowlist struct {
	ID          string
	Disabled    bool
	Description string
	Condition   string
	Commits     []string
	Paths       []string
	RegexTarget string
	Regexes     []string
	StopWords   []string
}

type viperGlobalAllowlist struct {
	TargetRules        []string
	viperRuleAllowlist `mapstructure:",squash"`
}

// Config is a configuration struct that contains rules and an allowlist if present.
type Config struct {
	Title       string
	Extend      Extend
	Path        string
	Description string
	Rules       map[string]Rule
	Keywords    map[string]struct{}
	// used to keep sarif results consistent
	OrderedRules []string
	Allowlists   []*Allowlist
	MinVersion   string
}

// Extend is a struct that allows users to define how they want their
// configuration extended by other configuration files.
type Extend struct {
	Path          string
	URL           string
	UseDefault    bool
	DisabledRules []string
	// DisabledAllowlists disables inherited global allowlist entries by ID.
	// Removing an entry never affects the other inherited entries.
	DisabledAllowlists []string
}

// Translate converts the Viper representation of the root configuration
// file into a fully merged, validated Config. The call is self-contained:
// inheritance resolution uses no package-level state, so configurations
// may be translated concurrently without interfering with each other.
func (vc *ViperConfig) Translate() (Config, error) {
	source := vc.configPath
	if source == "" {
		source = viper.ConfigFileUsed()
	}
	loader := newLoader()
	return loader.translate(vc, source)
}

// loader resolves an inheritance chain for a single Translate call. Every
// Translate creates its own loader, which guarantees that concurrent loads
// cannot share state.
type loader struct {
	// visited maps the resolved identity of every configuration in the
	// current chain to the chain position, for cycle detection.
	visited map[string]int
	// hops counts parent traversals to enforce maxExtendHops.
	hops int
}

func newLoader() *loader {
	return &loader{visited: make(map[string]int)}
}

// translate loads the root ViperConfig plus its whole inheritance chain,
// then folds the chain into a Config.
func (l *loader) translate(rootVC *ViperConfig, source string) (Config, error) {
	if source == "" {
		source = "<inline config>"
	}

	layers, err := l.loadChain(rootVC, source)
	if err != nil {
		return Config{}, err
	}

	cfg, err := mergeLayers(layers)
	if err != nil {
		return Config{}, err
	}

	if err := validateMinVersion(cfg.MinVersion, cfg.Path); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// loadChain walks the extend declarations from the root upwards and
// returns the layers ordered oldest-ancestor-first.
func (l *loader) loadChain(vc *ViperConfig, source string) ([]rawLayer, error) {
	if pos, ok := l.visited[source]; ok {
		return nil, fmt.Errorf("configuration inheritance cycle detected: %s (first reached at hop %d, revisited at hop %d)", source, pos, l.hops)
	}
	l.visited[source] = l.hops

	layer, err := parseLayer(vc, source)
	if err != nil {
		return nil, err
	}

	if !layer.extend.UseDefault && layer.extend.Path == "" {
		// Leaf of the chain.
		return []rawLayer{layer}, nil
	}
	if layer.extend.UseDefault && layer.extend.Path != "" {
		return nil, errors.New("unable to load config due to extend.path and extend.useDefault being set")
	}

	if l.hops >= maxExtendHops {
		return nil, fmt.Errorf("configuration inheritance depth exceeded the limit of %d parents while resolving %s", maxExtendHops, source)
	}
	l.hops++

	var parentVC *ViperConfig
	var parentSource string
	if layer.extend.UseDefault {
		parentVC, parentSource, err = l.readDefaultConfig()
	} else {
		parentVC, parentSource, err = l.readPathConfig(layer.extend.Path, source)
	}
	if err != nil {
		// An unreadable parent fails the whole load; we never degrade to
		// running with only the local rules.
		return nil, err
	}

	parentLayers, err := l.loadChain(parentVC, parentSource)
	if err != nil {
		return nil, err
	}
	return append(parentLayers, layer), nil
}

// readPathConfig reads a parent configuration from disk using a private
// Viper instance so global Viper state is never touched.
func (l *loader) readPathConfig(extendPath, childSource string) (*ViperConfig, string, error) {
	resolved := resolveExtendPath(extendPath, childSource)
	data, err := os.ReadFile(resolved)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load extended config %q: %w", extendPath, err)
	}

	v := viper.New()
	v.SetConfigType("toml")
	if err := v.ReadConfig(strings.NewReader(string(data))); err != nil {
		return nil, "", fmt.Errorf("failed to load extended config %q: %w", extendPath, err)
	}
	parentVC := &ViperConfig{}
	if err := v.Unmarshal(parentVC); err != nil {
		return nil, "", fmt.Errorf("failed to load extended config %q: %w", extendPath, err)
	}
	parentVC.configPath = resolved
	return parentVC, resolved, nil
}

// readDefaultConfig reads the embedded default configuration.
func (l *loader) readDefaultConfig() (*ViperConfig, string, error) {
	v := viper.New()
	v.SetConfigType("toml")
	if err := v.ReadConfig(strings.NewReader(DefaultConfig)); err != nil {
		return nil, "", fmt.Errorf("failed to load extended default config: %w", err)
	}
	parentVC := &ViperConfig{}
	if err := v.Unmarshal(parentVC); err != nil {
		return nil, "", fmt.Errorf("failed to load extended default config: %w", err)
	}
	logging.Debug().Msg("extending config with default config")
	return parentVC, DefaultConfigSource, nil
}

// resolveExtendPath resolves an extend.path value. Paths are first tried
// relative to the directory of the child configuration (the intuitive
// semantics); if that file does not exist, the original value is used
// unchanged so legacy configurations relying on CWD-relative paths keep
// working.
func resolveExtendPath(extendPath, childSource string) string {
	if filepath.IsAbs(extendPath) || childSource == DefaultConfigSource || childSource == "<inline config>" {
		return extendPath
	}
	relativeToChild := filepath.Join(filepath.Dir(childSource), extendPath)
	if _, err := os.Stat(relativeToChild); err == nil {
		return filepath.Clean(relativeToChild)
	}
	return extendPath
}

func validateMinVersion(minVer string, configPath string) error {
	if minVer == "" {
		logging.Debug().Str("config path", configPath).
			Msg("no minVersion specified in config... consider adding minVersion to ensure compatibility.")
		return nil
	}

	if version.Version == version.DefaultMsg {
		logging.Debug().
			Str("required", minVer).
			Msg("dev build, skipping config version check.")
		return nil
	}

	minSemVer, err := gv.NewSemver(minVer)
	if err != nil {
		return fmt.Errorf("invalid minVersion '%s': %w", minVer, err)
	}

	currentSemVer, err := gv.NewSemver(version.Version)
	if err != nil {
		return fmt.Errorf("unable to parse current version: %w", err)
	}

	if currentSemVer.LessThan(minSemVer) {
		logging.Warn().
			Str("required", minVer).
			Str("current", version.Version).
			Str("config path", configPath).
			Msg("config requires a newer Gitleaks version...")
	}

	return nil
}

// parseAllowlist compiles a raw allowlist declaration. It does not call
// Validate, which is deferred until the whole config has been assembled.
func parseAllowlist(a *viperRuleAllowlist) (*Allowlist, error) {
	var matchCondition AllowlistMatchCondition
	switch strings.ToUpper(a.Condition) {
	case "AND", "&&":
		matchCondition = AllowlistMatchAnd
	case "", "OR", "||":
		matchCondition = AllowlistMatchOr
	default:
		return nil, fmt.Errorf("unknown allowlist |condition| '%s' (expected 'and', 'or')", a.Condition)
	}

	// Validate the target.
	regexTarget := a.RegexTarget
	if regexTarget != "" {
		switch regexTarget {
		case "secret":
			regexTarget = ""
		case "match", "line":
			// do nothing
		default:
			return nil, fmt.Errorf("unknown allowlist |regexTarget| '%s' (expected 'match', 'line')", regexTarget)
		}
	}
	var allowlistRegexes []*regexp.Regexp
	for _, pattern := range a.Regexes {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		allowlistRegexes = append(allowlistRegexes, re)
	}
	var allowlistPaths []*regexp.Regexp
	for _, pattern := range a.Paths {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		allowlistPaths = append(allowlistPaths, re)
	}

	allowlist := &Allowlist{
		ID:             a.ID,
		Description:    a.Description,
		MatchCondition: matchCondition,
		Commits:        append([]string(nil), a.Commits...),
		Paths:          allowlistPaths,
		RegexTarget:    regexTarget,
		Regexes:        allowlistRegexes,
		StopWords:      append([]string(nil), a.StopWords...),
	}
	if err := allowlist.Validate(); err != nil {
		return nil, err
	}
	return allowlist, nil
}

// GetOrderedRules returns the rules in their stable declaration order.
func (c *Config) GetOrderedRules() []Rule {
	var orderedRules []Rule
	for _, id := range c.OrderedRules {
		if _, ok := c.Rules[id]; ok {
			orderedRules = append(orderedRules, c.Rules[id])
		}
	}
	return orderedRules
}

// allowlistIdentity returns the stable key used for entry-level merging.
// Explicit IDs win; otherwise a content fingerprint is used so identical
// entries inherited through repeated chains collapse instead of growing.
func allowlistIdentity(explicitID string, a *Allowlist) string {
	if explicitID != "" {
		return explicitID
	}
	h := sha256.New()
	fmt.Fprintf(h, "cond=%d|target=%s|desc=%s\n", a.MatchCondition, a.RegexTarget, a.Description)
	for _, c := range a.Commits {
		h.Write([]byte("commit:" + c + "\n"))
	}
	for _, r := range a.Regexes {
		h.Write([]byte("regex:" + r.String() + "\n"))
	}
	for _, p := range a.Paths {
		h.Write([]byte("path:" + p.String() + "\n"))
	}
	for _, s := range a.StopWords {
		h.Write([]byte("stop:" + s + "\n"))
	}
	return "fp:" + hex.EncodeToString(h.Sum(nil))
}
