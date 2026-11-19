package config

import (
	"fmt"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

// exportConfig is the serializable, regex-free representation of a merged
// Config used by ExportTOML. Only fields that can round-trip through the
// loader are emitted; internal bookkeeping is excluded.
type exportConfig struct {
	Title       string            `toml:"title,omitempty"`
	Description string            `toml:"description,omitempty"`
	MinVersion  string            `toml:"minVersion,omitempty"`
	Rules       []exportRule      `toml:"rules"`
	Allowlists  []exportAllowlist `toml:"allowlists,omitempty"`
}

type exportRule struct {
	ID          string            `toml:"id"`
	Description string            `toml:"description,omitempty"`
	Path        string            `toml:"path,omitempty"`
	Regex       string            `toml:"regex,omitempty"`
	SecretGroup int               `toml:"secretGroup,omitempty"`
	Entropy     float64           `toml:"entropy,omitempty"`
	Keywords    []string          `toml:"keywords,omitempty"`
	Tags        []string          `toml:"tags,omitempty"`
	SkipReport  bool              `toml:"skipReport,omitempty"`
	Priority    int               `toml:"priority,omitempty"`
	Allowlists  []exportRuleAllow `toml:"allowlists,omitempty"`
	Required    []exportRequired  `toml:"required,omitempty"`
}

type exportRequired struct {
	ID            string `toml:"id"`
	WithinLines   *int   `toml:"withinLines,omitempty"`
	WithinColumns *int   `toml:"withinColumns,omitempty"`
}

type exportRuleAllow struct {
	ID          string   `toml:"id,omitempty"`
	Description string   `toml:"description,omitempty"`
	Condition   string   `toml:"condition,omitempty"`
	Commits     []string `toml:"commits,omitempty"`
	Paths       []string `toml:"paths,omitempty"`
	RegexTarget string   `toml:"regexTarget,omitempty"`
	Regexes     []string `toml:"regexes,omitempty"`
	StopWords   []string `toml:"stopwords,omitempty"`
}

type exportAllowlist struct {
	ID          string   `toml:"id,omitempty"`
	Description string   `toml:"description,omitempty"`
	Condition   string   `toml:"condition,omitempty"`
	Commits     []string `toml:"commits,omitempty"`
	Paths       []string `toml:"paths,omitempty"`
	RegexTarget string   `toml:"regexTarget,omitempty"`
	Regexes     []string `toml:"regexes,omitempty"`
	StopWords   []string `toml:"stopwords,omitempty"`
	TargetRules []string `toml:"targetRules,omitempty"`
}

// ExportTOML serializes the fully merged Config into a standalone TOML
// document with no [extend] section. Re-loading the returned document
// yields an equivalent rule set: same rules, same declaration order, same
// allowlists and metadata. The receiver is not modified.
func (c *Config) ExportTOML() ([]byte, error) {
	exported := exportConfig{
		Title:       c.Title,
		Description: c.Description,
		MinVersion:  c.MinVersion,
	}

	for _, id := range c.OrderedRules {
		rule, ok := c.Rules[id]
		if !ok {
			return nil, fmt.Errorf("export: ordered rule ID '%s' has no rule entry", id)
		}

		er := exportRule{
			ID:          rule.RuleID,
			Description: rule.Description,
			SecretGroup: rule.SecretGroup,
			Entropy:     rule.Entropy,
			Keywords:    append([]string(nil), rule.Keywords...),
			Tags:        append([]string(nil), rule.Tags...),
			SkipReport:  rule.SkipReport,
			Priority:    rule.Priority,
		}
		if rule.Regex != nil {
			er.Regex = rule.Regex.String()
		}
		if rule.Path != nil {
			er.Path = rule.Path.String()
		}
		for _, a := range rule.Allowlists {
			er.Allowlists = append(er.Allowlists, exportRuleAllow{
				ID:          a.ID,
				Description: a.Description,
				Condition:   strings.ToLower(a.MatchCondition.String()),
				Commits:     append([]string(nil), a.Commits...),
				Paths:       regexStrings(a.Paths),
				RegexTarget: a.RegexTarget,
				Regexes:     regexStrings(a.Regexes),
				StopWords:   append([]string(nil), a.StopWords...),
			})
		}
		for _, req := range rule.RequiredRules {
			er.Required = append(er.Required, exportRequired{
				ID:            req.RuleID,
				WithinLines:   req.WithinLines,
				WithinColumns: req.WithinColumns,
			})
		}
		exported.Rules = append(exported.Rules, er)
	}

	for _, a := range c.Allowlists {
		exported.Allowlists = append(exported.Allowlists, exportAllowlist{
			ID:          a.ID,
			Description: a.Description,
			Condition:   strings.ToLower(a.MatchCondition.String()),
			Commits:     append([]string(nil), a.Commits...),
			Paths:       regexStrings(a.Paths),
			RegexTarget: a.RegexTarget,
			Regexes:     regexStrings(a.Regexes),
			StopWords:   append([]string(nil), a.StopWords...),
		})
	}

	// Targeted allowlists are stored on the rules themselves after merge,
	// so they are emitted through the rule loop above. The standalone
	// global list only contains untargeted entries.
	return toml.Marshal(exported)
}

func regexStrings(patterns []*regexp.Regexp) []string {
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, p.String())
	}
	return out
}
