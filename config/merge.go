package config

import (
	"fmt"
	"strings"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

// maxExtendHops is the maximum number of parent configurations a single
// load may traverse. Exceeding it fails the load with an explicit error
// instead of silently truncating the inheritance chain.
const maxExtendHops = 10

// rawRule is the per-layer representation of a rule declaration.
// Scalar fields use pointers so that an explicitly declared zero value
// (e.g. `entropy = 0`) is distinguishable from an undeclared field.
// Slice fields use pointer-to-slice for the same distinction: nil means
// undeclared while an empty, non-nil slice means "explicitly reset".
type rawRule struct {
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

	// Deprecated: shim for the singular [rules.allowlist] table.
	AllowList *viperRuleAllowlist

	Allowlists []*viperRuleAllowlist
	Required   []*viperRequired
}

// rawAllowlist is the per-layer representation of an allowlist entry.
// A non-nil Disabled entry removes a matching inherited entry without
// affecting the other entries.
type rawAllowlist struct {
	// ID optionally identifies an entry so child configurations can
	// disable or re-declare it.
	ID string

	Disabled bool

	Description string
	Condition   string
	Commits     []string
	Paths       []string
	RegexTarget string
	Regexes     []string
	StopWords   []string

	// TargetRules is only meaningful for global allowlists.
	TargetRules []string
}

// rawLayer is one configuration document in an inheritance chain,
// ordered from the oldest ancestor (index 0) to the root config.
type rawLayer struct {
	// source identifies where the layer came from. It is either an
	// absolute file path or DefaultConfigSource for the embedded config.
	source string

	title       string
	description string
	minVersion  string

	extend Extend

	rules      []rawRule
	allowlists []rawAllowlist
}

// DefaultConfigSource is the synthetic source identifier for the embedded
// default configuration, used in error messages and traceability fields.
const DefaultConfigSource = "<default config>"

// parseLayer converts a decoded ViperConfig into a rawLayer without
// compiling any regular expressions. Parsing is side-effect free and does
// not touch package-level state, so it is safe to run concurrently.
func parseLayer(vc *ViperConfig, source string) (rawLayer, error) {
	layer := rawLayer{
		source:      source,
		title:       vc.Title,
		description: vc.Description,
		minVersion:  vc.MinVersion,
		extend:      vc.Extend,
	}

	for _, vr := range vc.Rules {
		rr := rawRule{
			ID:          vr.ID,
			Description: vr.Description,
			Path:        vr.Path,
			Regex:       vr.Regex,
			SecretGroup: vr.SecretGroup,
			Entropy:     vr.Entropy,
			Keywords:    vr.Keywords,
			Tags:        vr.Tags,
			SkipReport:  vr.SkipReport,
			Priority:    vr.Priority,
			AllowList:   vr.AllowList,
			Allowlists:  vr.Allowlists,
			Required:    vr.Required,
		}
		layer.rules = append(layer.rules, rr)
	}
	// Backwards-compatible singular [allowlist] table.
	globalAllowlists := vc.Allowlists
	if vc.AllowList != nil {
		if len(globalAllowlists) > 0 {
			return rawLayer{}, fmt.Errorf("[allowlist] is deprecated, it cannot be used alongside [[allowlists]]")
		}
		globalAllowlists = []*viperGlobalAllowlist{vc.AllowList}
	}
	for _, a := range globalAllowlists {
		layer.allowlists = append(layer.allowlists, rawAllowlist{
			ID:          a.ID,
			Disabled:    a.Disabled,
			Description: a.Description,
			Condition:   a.Condition,
			Commits:     a.Commits,
			Paths:       a.Paths,
			RegexTarget: a.RegexTarget,
			Regexes:     a.Regexes,
			StopWords:   a.StopWords,
			TargetRules: a.TargetRules,
		})
	}

	return layer, nil
}

// mergeLayers folds an ordered list of layers (oldest ancestor first) into
// a single validated Config. Every merged value is freshly allocated: the
// input layers and the configurations behind them are never mutated.
func mergeLayers(layers []rawLayer) (Config, error) {
	if len(layers) == 0 {
		return Config{}, fmt.Errorf("internal error: mergeLayers called with no layers")
	}

	merged := newMergedState()

	for i, layer := range layers {
		if err := merged.applyLayer(layer); err != nil {
			// Root-layer errors keep their historical wording. Errors
			// originating in an inherited layer are prefixed with that
			// layer's source so the failing parent is identifiable.
			if i == len(layers)-1 {
				return Config{}, err
			}
			return Config{}, fmt.Errorf("%s: %w", layer.source, err)
		}
	}

	if err := merged.finalize(layers); err != nil {
		return Config{}, err
	}

	return merged.config, nil
}

// mergedState holds the accumulator while layers are folded.
type mergedState struct {
	config Config

	// ruleOrder records the declaration order of rule IDs.
	ruleOrder []string

	// globalAllowlistOrder records stable identities of global allowlist
	// entries: explicit ID when present, otherwise a content fingerprint.
	globalAllowlistOrder []string

	// ruleEntries mirrors ruleOrder but keeps the working rule data.
	ruleEntries map[string]*ruleState

	// globalAllowlists keeps global entries keyed by stable identity.
	globalAllowlists map[string]*Allowlist

	// targetedAllowlists accumulates allowlists that name target rules,
	// keyed by the target rule ID.
	targetedAllowlists map[string][]*Allowlist
}

type ruleState struct {
	rule Rule

	// allowlistOrder keeps stable identities of this rule's allowlist
	// entries in declaration order.
	allowlistOrder []string
	allowlists     map[string]*Allowlist

	// declared tracks whether the rule has been declared in at least one
	// layer (as opposed to only referenced by a disabled list).
	declared bool
}

func newMergedState() *mergedState {
	return &mergedState{
		config: Config{
			Rules:        make(map[string]Rule),
			Keywords:     make(map[string]struct{}),
			OrderedRules: []string{},
		},
		ruleEntries:        make(map[string]*ruleState),
		globalAllowlists:   make(map[string]*Allowlist),
		targetedAllowlists: make(map[string][]*Allowlist),
	}
}

func (m *mergedState) applyLayer(layer rawLayer) error {
	// Disabled rules must name rules that exist somewhere in the chain.
	// Existence is re-checked in finalize once every layer is applied.
	seenDisabled := make(map[string]struct{})
	for _, id := range layer.extend.DisabledRules {
		if _, dup := seenDisabled[id]; dup {
			return fmt.Errorf("[extend.disabledRules] rule ID '%s' is listed more than once", id)
		}
		seenDisabled[id] = struct{}{}
	}

	// Duplicate rule IDs within a single layer are rejected at load time.
	seenRuleID := make(map[string]struct{})
	for _, rr := range layer.rules {
		if strings.TrimSpace(rr.ID) == "" {
			// Preserve the historical error wording, including context.
			return fmt.Errorf("%s", missingIDError(rr))
		}
		if _, dup := seenRuleID[rr.ID]; dup {
			return fmt.Errorf("duplicate rule ID '%s': a rule ID may only be declared once per configuration file", rr.ID)
		}
		seenRuleID[rr.ID] = struct{}{}

		if err := m.applyRule(layer, rr); err != nil {
			return err
		}
	}

	if err := m.applyAllowlists(layer); err != nil {
		return err
	}

	return nil
}

func (m *mergedState) applyRule(layer rawLayer, rr rawRule) error {
	state, exists := m.ruleEntries[rr.ID]
	if !exists {
		state = &ruleState{
			rule: Rule{
				RuleID:   rr.ID,
				Keywords: []string{},
				Tags:     []string{},
			},
			allowlists: make(map[string]*Allowlist),
		}
		m.ruleEntries[rr.ID] = state
		m.ruleOrder = append(m.ruleOrder, rr.ID)
	}
	state.declared = true

	r := &state.rule
	r.RuleID = rr.ID

	// Scalar overrides: only an explicitly declared field replaces the
	// inherited value. A declared zero value replaces too, which is what
	// makes "reset this condition back to disabled" work.
	if rr.Description != nil {
		r.Description = *rr.Description
	}
	if rr.Path != nil {
		pat, err := compileOptionalPattern(*rr.Path)
		if err != nil {
			return fmt.Errorf("%s: %w", rr.ID, err)
		}
		r.Path = pat
	}
	if rr.Regex != nil {
		pat, err := compileOptionalPattern(*rr.Regex)
		if err != nil {
			return fmt.Errorf("%s: %w", rr.ID, err)
		}
		r.Regex = pat
	}
	if rr.SecretGroup != nil {
		r.SecretGroup = *rr.SecretGroup
	}
	if rr.Entropy != nil {
		r.Entropy = *rr.Entropy
	}
	if rr.SkipReport != nil {
		r.SkipReport = *rr.SkipReport
	}
	if rr.Priority != nil {
		r.Priority = *rr.Priority
		r.PrioritySource = layer.source
	}

	// Slice metadata. A nil pointer means "undeclared: keep the inherited
	// value". A non-nil pointer means "explicitly declared": an empty
	// slice clears the inherited list, while a non-empty slice replaces it.
	// De-duplication keeps repeated inheritance from growing the lists.
	if rr.Tags != nil {
		r.Tags = dedupePreserveOrder(*rr.Tags)
	}
	if rr.Keywords != nil {
		lowered := make([]string, len(*rr.Keywords))
		for i, k := range *rr.Keywords {
			lowered[i] = strings.ToLower(k)
		}
		r.Keywords = dedupePreserveOrder(lowered)
	}

	// Required rules: an explicit (even empty) declaration replaces the
	// inherited one; nil means inherit.
	if rr.Required != nil {
		r.RequiredRules = nil
		for _, req := range rr.Required {
			if req.ID == "" {
				return fmt.Errorf("%s: [[rules.required]] rule ID is empty", rr.ID)
			}
			r.RequiredRules = append(r.RequiredRules, &Required{
				RuleID:        req.ID,
				WithinLines:   req.WithinLines,
				WithinColumns: req.WithinColumns,
			})
		}
	}

	// Rule-level allowlists, including the deprecated singular form.
	ruleAllowlists := rr.Allowlists
	if rr.AllowList != nil {
		if len(ruleAllowlists) > 0 {
			return fmt.Errorf("%s: [rules.allowlist] is deprecated, it cannot be used alongside [[rules.allowlist]]", rr.ID)
		}
		ruleAllowlists = []*viperRuleAllowlist{rr.AllowList}
	}
	for _, a := range ruleAllowlists {
		if a.Disabled {
			if a.ID == "" {
				return fmt.Errorf("%s: a disabled [[rules.allowlists]] entry must declare an id", rr.ID)
			}
			if _, ok := state.allowlists[a.ID]; !ok {
				return fmt.Errorf("%s: disabled allowlist '%s' does not match any inherited allowlist", rr.ID, a.ID)
			}
			delete(state.allowlists, a.ID)
			state.allowlistOrder = removeString(state.allowlistOrder, a.ID)
			continue
		}

		compiled, err := parseAllowlist(a)
		if err != nil {
			return fmt.Errorf("%s: [[rules.allowlists]] %w", rr.ID, err)
		}
		if a.ID != "" {
			compiled.ID = a.ID
		}
		identity := allowlistIdentity(a.ID, compiled)
		if _, ok := state.allowlists[identity]; ok {
			// Same identity re-declared in a child: replace in place,
			// preserving the original declaration position.
			state.allowlists[identity] = compiled
		} else {
			state.allowlistOrder = append(state.allowlistOrder, identity)
			state.allowlists[identity] = compiled
		}
	}

	return nil
}

func (m *mergedState) applyAllowlists(layer rawLayer) error {
	// [extend.disabledAllowlists] removes inherited global entries before
	// this layer's own entries are processed. Removing an entry never
	// affects the other inherited entries.
	for _, id := range layer.extend.DisabledAllowlists {
		if _, ok := m.globalAllowlists[id]; !ok {
			return fmt.Errorf("[extend.disabledAllowlists] allowlist ID '%s' does not match any inherited allowlist", id)
		}
		delete(m.globalAllowlists, id)
		m.globalAllowlistOrder = removeString(m.globalAllowlistOrder, id)
	}

	for _, ra := range layer.allowlists {
		// A disabled entry never needs a body and must not be compiled.
		if ra.Disabled {
			identity := ra.ID
			if identity == "" {
				return fmt.Errorf("disabled [[allowlists]] entry must declare an id")
			}
			if _, ok := m.globalAllowlists[identity]; !ok {
				return fmt.Errorf("disabled allowlist '%s' does not match any inherited allowlist", identity)
			}
			delete(m.globalAllowlists, identity)
			m.globalAllowlistOrder = removeString(m.globalAllowlistOrder, identity)
			continue
		}

		compiled, err := parseAllowlist(&viperRuleAllowlist{
			Description: ra.Description,
			Condition:   ra.Condition,
			Commits:     ra.Commits,
			Paths:       ra.Paths,
			RegexTarget: ra.RegexTarget,
			Regexes:     ra.Regexes,
			StopWords:   ra.StopWords,
		})
		if err != nil {
			return fmt.Errorf("[[allowlists]] %w", err)
		}
		if ra.ID != "" {
			compiled.ID = ra.ID
		}
		identity := allowlistIdentity(ra.ID, compiled)

		if len(ra.TargetRules) > 0 {
			// Targeted entries never enter the global list. They are
			// attached during finalize once rule existence is known.
			for _, ruleID := range ra.TargetRules {
				m.targetedAllowlists[ruleID] = append(m.targetedAllowlists[ruleID], compiled)
			}
			continue
		}

		if _, ok := m.globalAllowlists[identity]; ok {
			m.globalAllowlists[identity] = compiled
		} else {
			m.globalAllowlistOrder = append(m.globalAllowlistOrder, identity)
			m.globalAllowlists[identity] = compiled
		}
	}

	return nil
}

// finalize performs whole-config validation that is only possible once
// every layer has been folded: disabled-rule existence, dangling
// references, rule validity, and stable ordering.
func (m *mergedState) finalize(layers []rawLayer) error {
	rootLayer := layers[len(layers)-1]

	// Collect every disabled rule ID mentioned across the chain and
	// verify it resolves to a declared rule.
	disabledRules := make(map[string]struct{})
	for _, layer := range layers {
		for _, id := range layer.extend.DisabledRules {
			disabledRules[id] = struct{}{}
		}
	}
	for id := range disabledRules {
		state, ok := m.ruleEntries[id]
		if !ok || !state.declared {
			return fmt.Errorf("[extend.disabledRules] rule ID '%s' does not exist", id)
		}
	}

	// Build the final rule set in declaration order, dropping disabled
	// rules and compiling each rule's allowlists.
	ordered := make([]string, 0, len(m.ruleOrder))
	for _, id := range m.ruleOrder {
		if _, off := disabledRules[id]; off {
			continue
		}
		state := m.ruleEntries[id]

		rule := state.rule // copy; slices below are already independently owned

		if len(state.allowlistOrder) > 0 {
			rule.Allowlists = make([]*Allowlist, 0, len(state.allowlistOrder))
			for _, identity := range state.allowlistOrder {
				rule.Allowlists = append(rule.Allowlists, state.allowlists[identity])
			}
		} else {
			rule.Allowlists = nil
		}

		if err := rule.Validate(); err != nil {
			return err
		}
		rule.order = len(ordered)
		m.config.Rules[id] = rule
		ordered = append(ordered, id)

		for _, k := range rule.Keywords {
			m.config.Keywords[k] = struct{}{}
		}
	}
	m.config.OrderedRules = ordered

	// Attach targeted global allowlists and verify the target rule exists.
	// Iterate in declaration order so the result does not depend on Go
	// map randomization.
	for _, id := range ordered {
		allowlists, ok := m.targetedAllowlists[id]
		if !ok {
			continue
		}
		rule := m.config.Rules[id]
		rule.Allowlists = append(rule.Allowlists, allowlists...)
		m.config.Rules[id] = rule
	}
	// Any target that named a rule absent from the final set is a
	// dangling reference and must fail the load.
	for ruleID := range m.targetedAllowlists {
		if _, ok := m.config.Rules[ruleID]; !ok {
			return fmt.Errorf("[[allowlists]] target rule ID '%s' does not exist", ruleID)
		}
	}

	// Re-validate rules that received targeted allowlists, then verify
	// required-rule references now that the full set is known.
	for _, id := range ordered {
		rule := m.config.Rules[id]
		for _, req := range rule.RequiredRules {
			if _, ok := m.config.Rules[req.RuleID]; !ok {
				return fmt.Errorf("%s: [[rules.required]] rule ID '%s' does not exist", id, req.RuleID)
			}
		}
	}

	// Global allowlists in stable identity order.
	if len(m.globalAllowlistOrder) > 0 {
		m.config.Allowlists = make([]*Allowlist, 0, len(m.globalAllowlistOrder))
		for _, identity := range m.globalAllowlistOrder {
			a := m.globalAllowlists[identity]
			if err := a.Validate(); err != nil {
				return fmt.Errorf("[[allowlists]] %w", err)
			}
			m.config.Allowlists = append(m.config.Allowlists, a)
		}
	}

	m.config.Extend = rootLayer.extend
	m.config.Path = rootLayer.source
	m.config.MinVersion = rootLayer.minVersion

	// Scalar metadata follows the historical semantics: the root
	// configuration's own value is the final value, exactly as a plain
	// struct assignment did before the merge rewrite.
	m.config.Title = rootLayer.title
	m.config.Description = rootLayer.description
	return nil
}

func compileOptionalPattern(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		// An explicitly empty string disables the condition.
		return nil, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return re, nil
}

// missingIDError reproduces the historical empty-ID error, including the
// description/regex context, so accepted configurations fail with the same
// wording they did before the merge rewrite.
func missingIDError(rr rawRule) string {
	var sb strings.Builder
	sb.WriteString("rule |id| is missing or empty")
	if rr.Description != nil && *rr.Description != "" {
		sb.WriteString(", description: " + *rr.Description)
	}
	if rr.Regex != nil && *rr.Regex != "" {
		sb.WriteString(", regex: " + *rr.Regex)
	}
	return sb.String()
}

func dedupePreserveOrder(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func removeString(items []string, target string) []string {
	out := items[:0]
	for _, item := range items {
		if item != target {
			out = append(out, item)
		}
	}
	return out
}
