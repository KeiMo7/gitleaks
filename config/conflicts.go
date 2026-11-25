package config

import (
	"sort"
	"strings"
)

// Stable conflict codes emitted by the allowlist adjudication machinery.
// They are part of the public diagnostic contract and must not be renamed.
const (
	// ConflictContradiction: the same declared value produces opposite
	// per-allowlist verdicts on the same candidate from two different sources.
	ConflictContradiction = "AL-CONFLICT-CONTRADICTION"

	// ConflictFieldUnavailable: an allowlist declares a field whose input is
	// structurally unavailable for the candidate (e.g. a content projection on
	// a path-only finding that carries no secret or line).
	ConflictFieldUnavailable = "AL-CONFLICT-FIELD-UNAVAILABLE"

	// ConflictDuplicate: two allowlists declared in different sources/layers
	// are synonymous (same condition, projections and value sets).
	ConflictDuplicate = "AL-CONFLICT-DUPLICATE"

	// ConflictUnknownRule: a targeted allowlist names a rule that does not
	// exist in the resolved configuration.
	ConflictUnknownRule = "AL-CONFLICT-UNKNOWN-RULE"
)

// AllowlistConflict is a single, deterministically ordered adjudication
// conflict. It carries only allowlist identifiers and positions — never
// scanned content or secret material.
type AllowlistConflict struct {
	// Code is one of the Conflict* constants.
	Code string `json:"code"`
	// AllowlistIDs are the stable identifiers of the involved allowlists.
	AllowlistIDs []string `json:"allowlistIds"`
	// Layer names the provenance layers involved.
	Layers []string `json:"layers"`
	// ConfigPaths are the declaring configuration files.
	ConfigPaths []string `json:"configPaths"`
	// RuleID is the targeted rule when the conflict is rule-scoped.
	RuleID string `json:"ruleId,omitempty"`
	// Detail is a fixed-phrase, content-free explanation.
	Detail string `json:"detail"`
}

// LoadConflict records a conflict discovered while the configuration was
// translated (before any scan input is read). It never contains scanned
// content.
type LoadConflict struct {
	Code         string
	AllowlistID  string
	Layer        string
	ConfigPath   string
	RuleID       string
	TargetRuleID string
	Detail       string
}

// Signature returns an order-independent content identity for the allowlist.
// Two allowlists with the same signature are synonymous regardless of their
// declaration position. It is built solely from the declaration (pattern
// strings and normalized literals), never from scanned content.
func (a *Allowlist) Signature() string {
	if a == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("cond=")
	b.WriteString(a.MatchCondition.String())
	b.WriteString("|target=")
	b.WriteString(a.regexTargetName())
	writeSorted := func(label string, values []string) {
		b.WriteString("|")
		b.WriteString(label)
		b.WriteString("=")
		cp := append([]string(nil), values...)
		sort.Strings(cp)
		b.WriteString(strings.Join(cp, ";"))
	}
	paths := make([]string, 0, len(a.Paths))
	for _, re := range a.Paths {
		paths = append(paths, re.String())
	}
	regexes := make([]string, 0, len(a.Regexes))
	for _, re := range a.Regexes {
		regexes = append(regexes, re.String())
	}
	writeSorted("commits", a.uniqueCommits)
	writeSorted("paths", paths)
	writeSorted("regexes", regexes)
	writeSorted("stopwords", a.uniqueStopWords)
	return b.String()
}

func (a *Allowlist) regexTargetName() string {
	switch a.RegexTarget {
	case "":
		return "secret"
	default:
		return a.RegexTarget
	}
}

// allowlistInventory flattens every allowlist in the resolved configuration
// into one deterministically ordered slice.
func (c *Config) allowlistInventory() []*Allowlist {
	var out []*Allowlist
	out = append(out, c.Allowlists...)
	for _, ruleID := range c.OrderedRules {
		rule, ok := c.Rules[ruleID]
		if !ok {
			continue
		}
		out = append(out, rule.Allowlists...)
	}
	return out
}

// AllowlistConflicts scans the resolved configuration for cross-source
// conflicts. The result is sorted by (code, allowlist IDs) so repeated runs
// produce byte-identical output. Scanning is never aborted by these; the
// conflicts are surfaced alongside the adjudication record.
func (c *Config) AllowlistConflicts() []AllowlistConflict {
	var conflicts []AllowlistConflict

	// Load-time conflicts (e.g. unknown target rules), re-keyed with the
	// allowlist stamp where one exists.
	for _, lc := range c.LoadConflicts {
		conflicts = append(conflicts, AllowlistConflict{
			Code:         lc.Code,
			AllowlistIDs: nonEmptyIDs(lc.AllowlistID),
			Layers:       nonEmptyIDs(lc.Layer),
			ConfigPaths:  nonEmptyIDs(lc.ConfigPath),
			RuleID:       lc.TargetRuleID,
			Detail:       lc.Detail,
		})
	}

	// Cross-source duplicates: synonymous allowlists declared in different
	// layers or different configuration files.
	bySignature := make(map[string][]*Allowlist)
	for _, a := range c.allowlistInventory() {
		if a == nil || a.Stamp == nil {
			continue
		}
		bySignature[a.Signature()] = append(bySignature[a.Signature()], a)
	}
	sigs := make([]string, 0, len(bySignature))
	for sig, group := range bySignature {
		if len(group) < 2 {
			continue
		}
		// Only treat as a duplicate when the declarations originate from
		// different sources (layer or config file).
		sources := make(map[string]struct{})
		for _, a := range group {
			sources[a.Stamp.Layer.String()+":"+a.Stamp.ConfigPath] = struct{}{}
		}
		if len(sources) < 2 {
			continue
		}
		sigs = append(sigs, sig)
	}
	sort.Strings(sigs)
	for _, sig := range sigs {
		group := bySignature[sig]
		sort.Slice(group, func(i, j int) bool {
			return group[i].Stamp.Ordinal < group[j].Stamp.Ordinal
		})
		conf := AllowlistConflict{
			Code:   ConflictDuplicate,
			Detail: "synonymous allowlists declared in multiple sources",
		}
		for _, a := range group {
			conf.AllowlistIDs = append(conf.AllowlistIDs, a.Stamp.ID)
			conf.Layers = append(conf.Layers, a.Stamp.Layer.String())
			conf.ConfigPaths = append(conf.ConfigPaths, a.Stamp.ConfigPath)
		}
		conflicts = append(conflicts, conf)
	}

	sort.SliceStable(conflicts, func(i, j int) bool {
		if conflicts[i].Code != conflicts[j].Code {
			return conflicts[i].Code < conflicts[j].Code
		}
		return strings.Join(conflicts[i].AllowlistIDs, ",") < strings.Join(conflicts[j].AllowlistIDs, ",")
	})
	return conflicts
}

func nonEmptyIDs(values ...string) []string {
	var out []string
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// dedupe returns values with duplicates removed, preserving first-seen order.
func dedupe(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
