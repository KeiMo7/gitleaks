package config

import (
	"errors"
	"fmt"
	"strings"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"golang.org/x/exp/maps"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

type AllowlistMatchCondition int

const (
	AllowlistMatchOr AllowlistMatchCondition = iota
	AllowlistMatchAnd
)

func (a AllowlistMatchCondition) String() string {
	return [...]string{
		"OR",
		"AND",
	}[a]
}

// AllowlistLayer identifies which of the four stacked ignore-rule layers an
// allowlist declaration belongs to. The ordering of the constants is the
// layers' canonical priority order (smaller == further from the rule, lower
// adjudication priority).
type AllowlistLayer int

const (
	// AllowlistLayerBuiltin is the layer embedded in the gitleaks binary
	// (the default config pulled in via extend.useDefault).
	AllowlistLayerBuiltin AllowlistLayer = iota + 1
	// AllowlistLayerExtension is the layer brought in through extend.path
	// (including further nested extension configs).
	AllowlistLayerExtension
	// AllowlistLayerGlobal is the layer of user-config global [[allowlists]],
	// both untargeted and rule-targeted (targetRules) declarations.
	AllowlistLayerGlobal
	// AllowlistLayerRule is the layer of a rule's own
	// [[rules.allowlists]], including folded legacy [rules.allowlist] blocks.
	AllowlistLayerRule
)

// String returns the stable, machine-readable layer name.
func (l AllowlistLayer) String() string {
	switch l {
	case AllowlistLayerBuiltin:
		return "builtin"
	case AllowlistLayerExtension:
		return "extension"
	case AllowlistLayerGlobal:
		return "global"
	case AllowlistLayerRule:
		return "rule"
	default:
		return fmt.Sprintf("unknown(%d)", int(l))
	}
}

// AllowlistScope records how a global allowlist is attached: globally to every
// rule, or only to the rules named in targetRules.
type AllowlistScope int

const (
	// AllowlistScopeGlobal applies the allowlist to every rule.
	AllowlistScopeGlobal AllowlistScope = iota + 1
	// AllowlistScopeTargeted applies the allowlist only to the target rules.
	AllowlistScopeTargeted
)

func (s AllowlistScope) String() string {
	switch s {
	case AllowlistScopeGlobal:
		return "global"
	case AllowlistScopeTargeted:
		return "targeted"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// AllowlistStamp carries the provenance and stable identity of an allowlist.
// The stamp is assigned while the configuration is translated and survives
// extension merging, rule targeting and legacy-block folding.
type AllowlistStamp struct {
	// ID is the stable identifier of the allowlist, unique within a resolved
	// configuration (e.g. "AL-0007"). It is derived from a global declaration
	// counter and therefore independent of map iteration and rule traversal.
	ID string

	// Ordinal is the zero-based declaration counter assigned when the
	// allowlist was parsed. Declaration order and in-layer position can be
	// reconstructed from it.
	Ordinal int

	// Layer is the allowlist's provenance layer.
	Layer AllowlistLayer

	// Scope is whether the allowlist is global or rule-targeted. Rule-layer
	// allowlists are always AllowlistScopeTargeted.
	Scope AllowlistScope

	// ConfigPath is the configuration file the allowlist was declared in.
	// The embedded default config is reported as "<default>".
	ConfigPath string

	// Kind is "allowlists" for the plural form or "allowlist" for the folded
	// legacy singular block.
	Kind string

	// Index is the zero-based position among the allowlist declarations of
	// the same kind in ConfigPath (i.e. the [[allowlists]] / [[rules.allowlists]]
	// table index, or 0 for a legacy singular block).
	Index int

	// RuleID is the owning rule for rule-layer and targeted allowlists,
	// empty for untargeted global allowlists.
	RuleID string

	// TargetRules holds the targetRules vector for targeted global allowlists.
	TargetRules []string
}

// Allowlist allows a rule to be ignored for specific
// regexes, paths, and/or commits
type Allowlist struct {
	// Short human readable description of the allowlist.
	Description string

	// MatchCondition determines whether all criteria must match. Defaults to "OR".
	MatchCondition AllowlistMatchCondition

	// Commits is a slice of commit SHAs that are allowed to be ignored.
	Commits []string

	// Paths is a slice of path regular expressions that are allowed to be ignored.
	Paths []*regexp.Regexp

	// Can be `match` or `line`.
	//
	// If `match` the _Regexes_ will be tested against the match of the _Rule.Regex_.
	//
	// If `line` the _Regexes_ will be tested against the entire line.
	//
	// If RegexTarget is empty, it will be tested against the found secret.
	RegexTarget string

	// Regexes is slice of content regular expressions that are allowed to be ignored.
	Regexes []*regexp.Regexp

	// StopWords is a slice of stop words that are allowed to be ignored.
	// This targets the _secret_, not the content of the regex match like the
	// Regexes slice.
	StopWords []string

	// Stamp is the provenance and identity record assigned during translation.
	// It is nil for allowlists constructed directly (e.g. in unit tests).
	Stamp *AllowlistStamp

	// validated is an internal flag to track whether `Validate()` has been called.
	validated bool

	// ordered, declaration-order-preserving unique values. The public slices
	// above retain their original contents; these fields are populated by
	// Validate() so adjudication can point at the exact declared value that
	// matched instead of reporting only the field name.
	uniqueCommits   []string
	uniqueStopWords []string

	// commitMap is a normalized version of Commits, used for efficiency purposes.
	// TODO: possible optimizations so that both short and long hashes work.
	commitMap    map[string]struct{}
	regexPat     *regexp.Regexp
	pathPat      *regexp.Regexp
	stopwordTrie *ahocorasick.Trie
}

// Stable error/conflict codes for load-time allowlist failures.
const (
	// LoadCodeEmptyAllowlist: an allowlist declares none of the four fields.
	LoadCodeEmptyAllowlist = "AL-LOAD-EMPTY-ALLOWLIST"
	// LoadCodeUnknownTargetRule: a targeted allowlist names a missing rule.
	LoadCodeUnknownTargetRule = "AL-LOAD-UNKNOWN-TARGET-RULE"
)

// ErrEmptyAllowlist is the sentinel returned by Validate for an allowlist that
// declares none of commits, paths, regexes or stopwords.
var ErrEmptyAllowlist = errors.New("must contain at least one check for: commits, paths, regexes, or stopwords")

func (a *Allowlist) Validate() error {
	if a.validated {
		return nil
	}

	// Disallow empty allowlists.
	if len(a.Commits) == 0 &&
		len(a.Paths) == 0 &&
		len(a.Regexes) == 0 &&
		len(a.StopWords) == 0 {
		return ErrEmptyAllowlist
	}

	// Deduplicate commits and stopwords while preserving declaration order.
	// The public slices keep their original contents for backwards
	// compatibility; deterministic, order-preserving unique copies are kept
	// for value-level adjudication.
	if len(a.Commits) > 0 {
		uniqueCommits := make(map[string]struct{})
		a.uniqueCommits = a.uniqueCommits[:0]
		for _, commit := range a.Commits {
			// Commits are case-insensitive.
			normalized := strings.TrimSpace(strings.ToLower(commit))
			if _, ok := uniqueCommits[normalized]; ok {
				continue
			}
			uniqueCommits[normalized] = struct{}{}
			a.uniqueCommits = append(a.uniqueCommits, normalized)
		}
		a.Commits = maps.Keys(uniqueCommits)
		a.commitMap = uniqueCommits
	}
	if len(a.StopWords) > 0 {
		uniqueStopwords := make(map[string]struct{})
		a.uniqueStopWords = a.uniqueStopWords[:0]
		for _, stopWord := range a.StopWords {
			normalized := strings.ToLower(stopWord)
			if _, ok := uniqueStopwords[normalized]; ok {
				continue
			}
			uniqueStopwords[normalized] = struct{}{}
			a.uniqueStopWords = append(a.uniqueStopWords, normalized)
		}

		values := maps.Keys(uniqueStopwords)
		a.StopWords = values
		a.stopwordTrie = ahocorasick.NewTrieBuilder().AddStrings(a.uniqueStopWords).Build()
	}

	// Combine patterns into a single expression.
	if len(a.Paths) > 0 {
		a.pathPat = joinRegexOr(a.Paths)
	}
	if len(a.Regexes) > 0 {
		a.regexPat = joinRegexOr(a.Regexes)
	}

	a.validated = true
	return nil
}

// CommitAllowed returns true if the commit is allowed to be ignored. When it
// is, the second return value is the normalized declared commit value that
// matched (empty string otherwise).
func (a *Allowlist) CommitAllowed(c string) (bool, string) {
	if a == nil || c == "" {
		return false, ""
	}
	normalized := strings.ToLower(c)
	if a.commitMap != nil {
		if _, ok := a.commitMap[normalized]; ok {
			return true, normalized
		}
	} else if len(a.Commits) > 0 {
		for _, commit := range a.Commits {
			if commit == c {
				return true, c
			}
		}
	}
	return false, ""
}

// CommitMatch returns whether the commit field matches and, when it does, the
// zero-based index (in declaration order) of the matching value in Commits.
func (a *Allowlist) CommitMatch(c string) (bool, int) {
	allowed, _ := a.CommitAllowed(c)
	if !allowed {
		return false, -1
	}
	normalized := strings.ToLower(c)
	for i, commit := range a.uniqueCommits {
		if commit == normalized {
			return true, i
		}
	}
	// Defensive fallback for unvalidated allowlists.
	for i, commit := range a.Commits {
		if strings.ToLower(commit) == normalized {
			return true, i
		}
	}
	return true, -1
}

// PathAllowed returns true if the path is allowed to be ignored.
func (a *Allowlist) PathAllowed(path string) bool {
	if a == nil || path == "" {
		return false
	}
	if a.pathPat != nil {
		return a.pathPat.MatchString(path)
	} else if len(a.Paths) > 0 {
		return anyRegexMatch(path, a.Paths)
	}
	return false
}

// PathMatch returns whether the path field matches and, when it does, the
// zero-based index (in declaration order) of the matching pattern in Paths.
func (a *Allowlist) PathMatch(path string) (bool, int) {
	if a == nil || path == "" {
		return false, -1
	}
	for i, re := range a.Paths {
		if regexMatched(path, re) {
			return true, i
		}
	}
	return false, -1
}

// RegexAllowed returns true if the regex is allowed to be ignored.
func (a *Allowlist) RegexAllowed(secret string) bool {
	if a == nil || secret == "" {
		return false
	}
	if a.regexPat != nil {
		return a.regexPat.MatchString(secret)
	} else if len(a.Regexes) > 0 {
		return anyRegexMatch(secret, a.Regexes)
	}
	return false
}

// RegexMatch returns whether the regexes field matches and, when it does, the
// zero-based index (in declaration order) of the matching pattern in Regexes.
// |target| is the projection selected by RegexTarget: secret, match or line.
func (a *Allowlist) RegexMatch(target string) (bool, int) {
	if a == nil || target == "" {
		return false, -1
	}
	for i, re := range a.Regexes {
		if regexMatched(target, re) {
			return true, i
		}
	}
	return false, -1
}

func (a *Allowlist) ContainsStopWord(s string) (bool, string) {
	if a == nil || s == "" {
		return false, ""
	}

	s = strings.ToLower(s)
	if a.stopwordTrie != nil {
		if m := a.stopwordTrie.MatchFirstString(s); m != nil {
			return true, m.MatchString()
		}
	} else if len(a.StopWords) > 0 {
		for _, stopWord := range a.StopWords {
			if strings.Contains(s, stopWord) {
				return true, stopWord
			}
		}
	}
	return false, ""
}

// StopWordMatch returns whether the stopwords field matches and, when it does,
// the zero-based index (in declaration order) of the matching stop word.
func (a *Allowlist) StopWordMatch(s string) (bool, int) {
	allowed, word := a.ContainsStopWord(s)
	if !allowed {
		return false, -1
	}
	for i, stopWord := range a.uniqueStopWords {
		if stopWord == word {
			return true, i
		}
	}
	// Defensive fallback for unvalidated allowlists.
	for i, stopWord := range a.StopWords {
		if strings.ToLower(stopWord) == word {
			return true, i
		}
	}
	return true, -1
}

// Identity returns the stable allowlist ID when a stamp is present, otherwise
// a deterministic placeholder derived from the allowlist pointer.
func (a *Allowlist) Identity() string {
	if a.Stamp != nil && a.Stamp.ID != "" {
		return a.Stamp.ID
	}
	return fmt.Sprintf("AL-ADHOC-%p", a)
}
