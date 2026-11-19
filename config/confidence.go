package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/viper"
)

// ConfidenceSchemaVersion is the only schema version understood by this
// build. A confidence configuration carrying any other version is rejected
// rather than silently interpreted with different semantics.
const ConfidenceSchemaVersion = "1"

// ConfidenceConfig configures the joint rule/entropy confidence decision.
//
// The zero value (Enabled == false) means the feature is off and the
// detector must behave exactly like it did before the feature existed.
// Every tunable used by the decision engine lives here; there are no magic
// numbers in the detection code.
type ConfidenceConfig struct {
	// Enabled gates the whole feature. Nothing in this struct has any effect
	// while Enabled is false.
	Enabled bool

	// SchemaVersion guards against loading a config written for a different
	// decision-engine version.
	SchemaVersion string

	// Decision holds the report/veto thresholds.
	Decision ConfidenceDecision

	// Scoring holds the weights and base scores used to build a confidence.
	Scoring ConfidenceScoring

	// Entropy holds the entropy gate replacement thresholds.
	Entropy ConfidenceEntropy

	// Prefixes are literal credential prefixes (e.g. "ghp_", "xoxb-") that
	// mark a match as structurally credential-like even when it is short.
	Prefixes []string

	// Resource describes high-entropy-but-benign build/resource strings that
	// must not trigger on their own.
	Resource ConfidenceResource

	// Cluster groups similar hits inside the same file into one finding.
	Cluster ConfidenceCluster

	// Marks points at the persistent, revocable false-positive store.
	Marks ConfidenceMarks

	// RedactSecrets is retained for backwards-compatible config parsing but is
	// intentionally ignored: the joint pipeline always redacts secret material
	// at every reporting/logging boundary because that is a hard constraint.
	// In-process Detect() return values are not redacted so library callers
	// can still inspect findings programmatically.
	RedactSecrets bool

	// resourceContentRegexes and resourcePathRegexes are the compiled forms
	// of the Resource patterns, built once at load time. They keep scanning
	// from recompiling a regex for every finding. Not serialized.
	resourceContentRegexes []*regexp.Regexp
	resourcePathRegexes    []*regexp.Regexp
}

// ResourceContentRegexes returns the compiled resource content patterns,
// compiling them lazily exactly once (and skipping invalid patterns).
func (c *ConfidenceConfig) ResourceContentRegexes() []*regexp.Regexp {
	if c.resourceContentRegexes == nil {
		c.resourceContentRegexes = compileAll(c.Resource.ContentPatterns)
	}
	return c.resourceContentRegexes
}

// ResourcePathRegexes returns the compiled resource path patterns.
func (c *ConfidenceConfig) ResourcePathRegexes() []*regexp.Regexp {
	if c.resourcePathRegexes == nil {
		c.resourcePathRegexes = compileAll(c.Resource.PathPatterns)
	}
	return c.resourcePathRegexes
}

func compileAll(patterns []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		out = append(out, re)
	}
	return out
}

// ConfidenceDecision holds the accept/veto thresholds.
type ConfidenceDecision struct {
	// ReportThreshold is the minimum confidence required to emit a finding.
	ReportThreshold float64

	// HighConfidenceThreshold is the minimum confidence labelled "high";
	// everything at or above ReportThreshold but below it is "medium".
	HighConfidenceThreshold float64
}

// ConfidenceScoring holds every weight used by the additive score.
type ConfidenceScoring struct {
	// NamedRuleBase is the base score when a named rule matches.
	NamedRuleBase float64

	// GenericRuleBase is the base score when only a generic rule matches.
	GenericRuleBase float64

	// EntropyHigh is added when entropy exceeds Entropy.HighThreshold.
	EntropyHigh float64

	// EntropyLow is added when entropy is at or above the (legacy) rule
	// entropy threshold but below the high threshold.
	EntropyLow float64

	// KnownPrefix is added when a configured credential prefix is present.
	KnownPrefix float64

	// ResourcePenalty is subtracted for every resource indicator hit.
	ResourcePenalty float64
}

// ConfidenceEntropy replaces the single hard entropy gate when enabled.
type ConfidenceEntropy struct {
	// HighThreshold is the entropy above which a string is treated as a
	// strong randomness signal rather than a hard requirement.
	HighThreshold float64

	// VetoHighEntropyOnly suppresses findings whose only signal is high
	// entropy and which also look like build/resource material.
	VetoHighEntropyOnly bool
}

// ConfidenceResource describes benign high-entropy material.
type ConfidenceResource struct {
	// ContentPatterns are regexes matched against the candidate secret.
	ContentPatterns []string

	// PathPatterns are regexes matched against the fragment file path.
	PathPatterns []string

	// StopWords are lowercase substrings; any occurrence counts as a hit.
	StopWords []string

	// MinHits is the number of resource indicators required to veto a
	// high-entropy-only finding.
	MinHits int
}

// ConfidenceCluster configures same-file similar-hit merging.
type ConfidenceCluster struct {
	// Enabled turns clustering on.
	Enabled bool

	// SimilarityThreshold is the bigram-Jaccard similarity at or above which
	// two hits in one file are considered the same underlying secret.
	SimilarityThreshold float64
}

// ConfidenceMarks configures the revocable false-positive store.
type ConfidenceMarks struct {
	// Path is the JSON file holding suppressed/revoked fingerprints.
	Path string
}

// ViperConfidence is the on-disk (TOML) representation. It stays separate
// from ConfidenceConfig so that parsed regexes/derived data never leak back
// into serialization.
type ViperConfidence struct {
	Enabled       bool                     `mapstructure:"enabled"`
	SchemaVersion string                   `mapstructure:"schema_version"`
	Decision      *ViperConfidenceDecision `mapstructure:"decision"`
	Scoring       *ViperConfidenceScoring  `mapstructure:"scoring"`
	Entropy       *ViperConfidenceEntropy  `mapstructure:"entropy"`
	Prefixes      []string                 `mapstructure:"prefixes"`
	Resource      *ViperConfidenceResource `mapstructure:"resource"`
	Cluster       *ViperConfidenceCluster  `mapstructure:"cluster"`
	Marks         *ViperConfidenceMarks    `mapstructure:"marks"`
	RedactSecrets bool                     `mapstructure:"redact_secrets"`
}

type ViperConfidenceDecision struct {
	ReportThreshold         float64 `mapstructure:"report_threshold"`
	HighConfidenceThreshold float64 `mapstructure:"high_confidence_threshold"`
}

type ViperConfidenceScoring struct {
	NamedRuleBase   float64 `mapstructure:"named_rule_base"`
	GenericRuleBase float64 `mapstructure:"generic_rule_base"`
	EntropyHigh     float64 `mapstructure:"entropy_high"`
	EntropyLow      float64 `mapstructure:"entropy_low"`
	KnownPrefix     float64 `mapstructure:"known_prefix"`
	ResourcePenalty float64 `mapstructure:"resource_penalty"`
}

type ViperConfidenceEntropy struct {
	HighThreshold       float64 `mapstructure:"high_threshold"`
	VetoHighEntropyOnly bool    `mapstructure:"veto_high_entropy_only"`
}

type ViperConfidenceResource struct {
	ContentPatterns []string `mapstructure:"content_patterns"`
	PathPatterns    []string `mapstructure:"path_patterns"`
	StopWords       []string `mapstructure:"stop_words"`
	MinHits         int      `mapstructure:"min_hits"`
}

type ViperConfidenceCluster struct {
	Enabled             bool    `mapstructure:"enabled"`
	SimilarityThreshold float64 `mapstructure:"similarity_threshold"`
}

type ViperConfidenceMarks struct {
	Path string `mapstructure:"path"`
}

// DefaultConfidenceConfig returns the built-in thresholds. These defaults
// are the single source of truth both for normal operation and for degraded
// operation when an external config cannot be read.
func DefaultConfidenceConfig() ConfidenceConfig {
	return ConfidenceConfig{
		Enabled:       false,
		SchemaVersion: ConfidenceSchemaVersion,
		Decision: ConfidenceDecision{
			ReportThreshold:         0.45,
			HighConfidenceThreshold: 0.75,
		},
		Scoring: ConfidenceScoring{
			NamedRuleBase:   0.40,
			GenericRuleBase: 0.20,
			EntropyHigh:     0.25,
			EntropyLow:      0.10,
			KnownPrefix:     0.45,
			ResourcePenalty: 0.20,
		},
		Entropy: ConfidenceEntropy{
			HighThreshold:       4.0,
			VetoHighEntropyOnly: true,
		},
		Prefixes: []string{
			"ghp_", "gho_", "ghu_", "ghs_", "ghr_",
			"xoxb-", "xoxp-", "xoxa-", "xoxr-",
			"AKIA", "ASIA", "ACCA", "ABIA",
			"sk_live_", "rk_live_",
			"shpat_", "shpss_", "shpca_", "shppa_",
			"AIza", "SG.", "dt0",
		},
		Resource: ConfidenceResource{
			ContentPatterns: []string{
				// long base64/hex blobs, UUID-like build ids, dotted versions
				`^[A-Za-z0-9+/=_-]{32,}$`,
				`^[0-9a-f]{32,}$`,
				`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`,
				`^\d+\.\d+\.\d+(?:[.-][0-9A-Za-z]+)*$`,
			},
			PathPatterns: []string{
				`(?:^|/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|go\.sum|Cargo\.lock|poetry\.lock)$`,
				`\.(?:min\.js|min\.css|map|wasm|png|jpe?g|gif|zip|tar|gz|jar|pyc|ico|woff2?)$`,
				`(?:^|/)(?:dist|build|out|target|vendor|node_modules)(?:/|$)`,
			},
			StopWords: []string{
				"build", "version", "revision", "checksum", "sha256",
				"package", "artifact", "bundle", "release",
			},
			MinHits: 2,
		},
		Cluster: ConfidenceCluster{
			Enabled:             true,
			SimilarityThreshold: 0.85,
		},
		Marks: ConfidenceMarks{
			Path: ".gitleaks-marks.json",
		},
		RedactSecrets: true,
	}
}

// Translate converts the on-disk representation into a validated runtime
// config. Unset fields inherit the built-in defaults so partial files work.
func (vc *ViperConfidence) Translate() (ConfidenceConfig, error) {
	cfg := DefaultConfidenceConfig()
	cfg.Enabled = vc.Enabled
	cfg.RedactSecrets = vc.RedactSecrets
	if vc.SchemaVersion != "" {
		cfg.SchemaVersion = vc.SchemaVersion
	}
	if len(vc.Prefixes) > 0 {
		cfg.Prefixes = vc.Prefixes
	}

	if vc.Decision != nil {
		if vc.Decision.ReportThreshold != 0 {
			cfg.Decision.ReportThreshold = vc.Decision.ReportThreshold
		}
		if vc.Decision.HighConfidenceThreshold != 0 {
			cfg.Decision.HighConfidenceThreshold = vc.Decision.HighConfidenceThreshold
		}
	}
	if vc.Scoring != nil {
		s := vc.Scoring
		if s.NamedRuleBase != 0 {
			cfg.Scoring.NamedRuleBase = s.NamedRuleBase
		}
		if s.GenericRuleBase != 0 {
			cfg.Scoring.GenericRuleBase = s.GenericRuleBase
		}
		if s.EntropyHigh != 0 {
			cfg.Scoring.EntropyHigh = s.EntropyHigh
		}
		if s.EntropyLow != 0 {
			cfg.Scoring.EntropyLow = s.EntropyLow
		}
		if s.KnownPrefix != 0 {
			cfg.Scoring.KnownPrefix = s.KnownPrefix
		}
		if s.ResourcePenalty != 0 {
			cfg.Scoring.ResourcePenalty = s.ResourcePenalty
		}
	}
	if vc.Entropy != nil {
		if vc.Entropy.HighThreshold != 0 {
			cfg.Entropy.HighThreshold = vc.Entropy.HighThreshold
		}
		cfg.Entropy.VetoHighEntropyOnly = vc.Entropy.VetoHighEntropyOnly
	}
	if vc.Resource != nil {
		if len(vc.Resource.ContentPatterns) > 0 {
			cfg.Resource.ContentPatterns = vc.Resource.ContentPatterns
		}
		if len(vc.Resource.PathPatterns) > 0 {
			cfg.Resource.PathPatterns = vc.Resource.PathPatterns
		}
		if len(vc.Resource.StopWords) > 0 {
			cfg.Resource.StopWords = vc.Resource.StopWords
		}
		if vc.Resource.MinHits != 0 {
			cfg.Resource.MinHits = vc.Resource.MinHits
		}
	}
	if vc.Cluster != nil {
		cfg.Cluster.Enabled = vc.Cluster.Enabled
		if vc.Cluster.SimilarityThreshold != 0 {
			cfg.Cluster.SimilarityThreshold = vc.Cluster.SimilarityThreshold
		}
	}
	if vc.Marks != nil && vc.Marks.Path != "" {
		cfg.Marks.Path = vc.Marks.Path
	}

	return cfg, cfg.Validate()
}

// Validate guards against configs the engine cannot interpret safely.
func (c ConfidenceConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.SchemaVersion != ConfidenceSchemaVersion {
		return fmt.Errorf("confidence config schema_version %q is not supported (this build supports %q)",
			c.SchemaVersion, ConfidenceSchemaVersion)
	}
	if c.Decision.ReportThreshold <= 0 || c.Decision.ReportThreshold > 1 {
		return fmt.Errorf("confidence decision.report_threshold must be within (0,1], got %v", c.Decision.ReportThreshold)
	}
	if c.Decision.HighConfidenceThreshold < c.Decision.ReportThreshold || c.Decision.HighConfidenceThreshold > 1 {
		return fmt.Errorf("confidence decision.high_confidence_threshold (%.2f) must be within [report_threshold (%.2f),1]",
			c.Decision.HighConfidenceThreshold, c.Decision.ReportThreshold)
	}
	if c.Entropy.HighThreshold <= 0 {
		return fmt.Errorf("confidence entropy.high_threshold must be positive, got %v", c.Entropy.HighThreshold)
	}
	if c.Resource.MinHits < 1 {
		return fmt.Errorf("confidence resource.min_hits must be >= 1, got %d", c.Resource.MinHits)
	}
	if c.Cluster.Enabled && (c.Cluster.SimilarityThreshold <= 0 || c.Cluster.SimilarityThreshold > 1) {
		return fmt.Errorf("confidence cluster.similarity_threshold must be within (0,1], got %v", c.Cluster.SimilarityThreshold)
	}
	for _, w := range []float64{
		c.Scoring.NamedRuleBase, c.Scoring.GenericRuleBase, c.Scoring.EntropyHigh,
		c.Scoring.EntropyLow, c.Scoring.KnownPrefix, c.Scoring.ResourcePenalty,
	} {
		if w < 0 {
			return fmt.Errorf("confidence scoring weights must be non-negative, got %v", w)
		}
	}
	for _, p := range c.Resource.ContentPatterns {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("confidence resource.content_patterns has invalid regex %q: %w", p, err)
		}
	}
	for _, p := range c.Resource.PathPatterns {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("confidence resource.path_patterns has invalid regex %q: %w", p, err)
		}
	}
	return nil
}

// LoadConfidenceConfig reads a standalone confidence config file.
//
// A missing/unreadable/malformed file is NOT fatal: the built-in defaults
// (enabled) are returned together with a non-nil DegradedError explaining
// the fallback, so the scan can continue with a clearly reported degraded
// status. A schema-version mismatch is a hard error because silently
// reinterpreting unknown fields would change decisions.
func LoadConfidenceConfig(path string) (ConfidenceConfig, *DegradedConfigError) {
	if strings.TrimSpace(path) == "" {
		return DefaultConfidenceConfig(), nil
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		return degraded(path, fmt.Errorf("cannot read confidence config: %w", err))
	}

	v := viper.New()
	v.SetConfigType("toml")
	if err := v.ReadConfig(strings.NewReader(string(bytes))); err != nil {
		return degraded(path, fmt.Errorf("cannot parse confidence config: %w", err))
	}

	var vc ViperConfidence
	if err := v.Unmarshal(&vc); err != nil {
		return degraded(path, fmt.Errorf("cannot decode confidence config: %w", err))
	}

	cfg, err := vc.Translate()
	if err != nil {
		// Schema mismatch and invalid values must not be papered over.
		return DefaultConfidenceConfig(), &DegradedConfigError{Path: path, Err: err, HardReject: true}
	}
	return cfg, nil
}

func degraded(path string, err error) (ConfidenceConfig, *DegradedConfigError) {
	cfg := DefaultConfidenceConfig()
	cfg.Enabled = true
	return cfg, &DegradedConfigError{Path: path, Err: err}
}

// DegradedConfigError reports that an external confidence config could not
// be used and built-in defaults were substituted.
type DegradedConfigError struct {
	Path       string
	Err        error
	HardReject bool
}

func (e *DegradedConfigError) Error() string {
	kind := "falling back to built-in default confidence thresholds"
	if e.HardReject {
		kind = "refusing to load confidence config"
	}
	return fmt.Sprintf("confidence config %q: %v; %s", e.Path, e.Err, kind)
}

func (e *DegradedConfigError) Unwrap() error { return e.Err }
