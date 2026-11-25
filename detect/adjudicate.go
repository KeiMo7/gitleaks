package detect

import (
	"sort"
	"sync"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

// Adjudication stages. The same allowlist evaluation machinery produces the
// verdict for both stages; the stage only selects which fields participate in
// the legacy-compatible merge decision.
const (
	stageFile    = "file"
	stageFinding = "finding"
)

// Adjudication field names — these are the four declared allowlist fields.
const (
	fieldCommit   = "commit"
	fieldPath     = "path"
	fieldRegex    = "regex"
	fieldStopword = "stopword"
)

// Per-field tri-state-plus statuses. "not-declared" means the allowlist does
// not declare the field; "not-applicable" means the field is declared but the
// candidate carries no usable input for it, or the field is outside the
// merge scope of the current stage.
const (
	statusTrue          = "true"
	statusFalse         = "false"
	statusNotDeclared   = "not-declared"
	statusNotApplicable = "not-applicable"
)

// Text projections selectable by allowlist.regexTarget.
const (
	projectionSecret = "secret"
	projectionMatch  = "match"
	projectionLine   = "line"
)

// FieldVerdict is the per-field adjacency vector element. It never carries
// scanned content: the declared value is referenced by its declaration index.
type FieldVerdict struct {
	Field      string `json:"field"`
	Status     string `json:"status"`
	ValueIndex int    `json:"valueIndex"`
	// InMerge reports whether the field participates in the allowlist's
	// stage-level merge decision.
	InMerge bool `json:"inMerge"`
	// Projection is set for the regex field: secret, match or line.
	Projection string `json:"projection,omitempty"`
}

// AllowlistVerdict is one allowlist's full vector against one candidate at
// one stage.
type AllowlistVerdict struct {
	AllowlistID string         `json:"allowlistId"`
	Layer       string         `json:"layer"`
	Scope       string         `json:"scope"`
	ConfigPath  string         `json:"configPath"`
	Kind        string         `json:"kind"`
	Ordinal     int            `json:"ordinal"`
	Position    string         `json:"position"`
	Condition   string         `json:"condition"`
	Stage       string         `json:"stage"`
	Suppresses  bool           `json:"suppresses"`
	Matched     bool           `json:"matched"`
	Fields      []FieldVerdict `json:"fields"`
	// ConflictCodes references runtime conflicts observed on this verdict.
	ConflictCodes []string `json:"conflictCodes,omitempty"`
}

// CandidateRef identifies the adjudicated candidate without secret material.
type CandidateRef struct {
	RuleID      string `json:"ruleId"`
	File        string `json:"file"`
	Commit      string `json:"commit,omitempty"`
	StartLine   int    `json:"startLine"`
	StartColumn int    `json:"startColumn"`
	EndLine     int    `json:"endLine"`
	EndColumn   int    `json:"endColumn"`
}

// Record is the persisted adjudication record for one adjudicated candidate.
type Record struct {
	// Decision is "suppressed" or "retained".
	Decision    string       `json:"decision"`
	Stage       string       `json:"stage"`
	Reason      string       `json:"reason"`
	Adjudicator string       `json:"adjudicator,omitempty"`
	AdjLayer    string       `json:"adjudicatorLayer,omitempty"`
	Candidate   CandidateRef `json:"candidate"`
	// HitIDs lists every allowlist whose verdict suppresses, in the
	// deterministic total order. The first one is the adjudicator.
	HitIDs   []string           `json:"hitAllowlistIds,omitempty"`
	Verdicts []AllowlistVerdict `json:"verdicts"`
}

// LayerLedger is the per-layer accounting block.
type LayerLedger struct {
	Layer           string `json:"layer"`
	Suppressed      int    `json:"suppressed"`
	Evaluated       int    `json:"evaluated"`
	NoHitAllowlists int    `json:"noHitAllowlists"`
	Conflicts       int    `json:"conflicts"`
}

// Summary is the deterministic accounting block written with the record set.
type Summary struct {
	TotalCandidates int            `json:"totalCandidates"`
	Suppressed      int            `json:"suppressed"`
	Retained        int            `json:"retained"`
	ByLayer         []LayerLedger  `json:"byLayer"`
	ConflictCounts  map[string]int `json:"conflictCounts"`
	// Non-allowlist suppression channels, kept separate from the four layers.
	InlineCommentSuppressed  int `json:"inlineCommentSuppressed"`
	GitleaksIgnoreSuppressed int `json:"gitleaksIgnoreSuppressed"`
	BaselineSuppressed       int `json:"baselineSuppressed"`
}

// AdjudicationReport is the single, atomically-written adjudication artifact.
type AdjudicationReport struct {
	Version   string                     `json:"version"`
	Summary   Summary                    `json:"summary"`
	Conflicts []config.AllowlistConflict `json:"conflicts"`
	Records   []Record                   `json:"records"`
}

const adjudicationVersion = "1.0"

// Adjudicator collects structured allowlist adjudications while a scan runs.
// It is safe for concurrent use; output is produced once, at scan finalize.
type Adjudicator struct {
	mu sync.Mutex

	records   []Record
	conflicts map[string]config.AllowlistConflict

	// matchedAllowlistIDs records every allowlist that matched at least once,
	// keyed by stable ID. Layer/config of each ID is kept for the no-hit
	// accounting at finalize.
	matched   map[string]struct{}
	inventory map[string]*config.Allowlist

	suppressedByLayer  map[string]int
	evaluatedByLayer   map[string]int
	inlineSuppressed   int
	ignoreSuppressed   int
	baselineSuppressed int
}

// NewAdjudicator builds an adjudicator over the resolved configuration's
// complete allowlist inventory.
func NewAdjudicator(cfg config.Config) *Adjudicator {
	a := &Adjudicator{
		conflicts:         make(map[string]config.AllowlistConflict),
		matched:           make(map[string]struct{}),
		inventory:         make(map[string]*config.Allowlist),
		suppressedByLayer: make(map[string]int),
		evaluatedByLayer:  make(map[string]int),
	}
	for _, al := range cfg.Allowlists {
		if al != nil && al.Stamp != nil {
			a.inventory[al.Stamp.ID] = al
		}
	}
	for _, ruleID := range cfg.OrderedRules {
		rule, ok := cfg.Rules[ruleID]
		if !ok {
			continue
		}
		for _, al := range rule.Allowlists {
			if al != nil && al.Stamp != nil {
				a.inventory[al.Stamp.ID] = al
			}
		}
	}
	for _, conflict := range cfg.AllowlistConflicts() {
		a.conflicts[conflictKey(conflict)] = conflict
	}
	return a
}

func conflictKey(c config.AllowlistConflict) string {
	return c.Code + "|" + joinIDs(c.AllowlistIDs)
}

func joinIDs(ids []string) string {
	out := ""
	for i, id := range ids {
		if i > 0 {
			out += ","
		}
		out += id
	}
	return out
}

// evaluation is the pure result of adjudicating one list set against a
// candidate at one stage.
type evaluation struct {
	verdicts    []AllowlistVerdict
	suppresses  bool
	adjudicator *AllowlistVerdict
	hits        []AllowlistVerdict
}

// evaluateAdjudication runs the unified, per-field adjudication over the
// provided allowlist list set. The merge rules reproduce the historical
// file/finding two-stage decisions exactly; the vectors additionally expose
// every field's status and the matching declared value's index.
func evaluateAdjudication(fragment Fragment, finding *report.Finding, currentLine string, stage string, allowlists []*config.Allowlist) evaluation {
	var (
		verdicts = make([]AllowlistVerdict, 0)
		hits     = make([]AllowlistVerdict, 0)
	)

	for _, a := range allowlists {
		if a == nil {
			continue
		}
		v := AllowlistVerdict{
			Stage:     stage,
			Condition: a.MatchCondition.String(),
			Fields:    []FieldVerdict{},
		}
		if a.Stamp != nil {
			v.AllowlistID = a.Stamp.ID
			v.Layer = a.Stamp.Layer.String()
			v.Scope = a.Stamp.Scope.String()
			v.ConfigPath = a.Stamp.ConfigPath
			v.Kind = a.Stamp.Kind
			v.Ordinal = a.Stamp.Ordinal
			v.Position = adjudicationPosition(a)
		} else {
			v.AllowlistID = a.Identity()
			v.Layer = "ad-hoc"
			v.Scope = "ad-hoc"
		}

		commitInput := fragment.CommitSHA
		pathInput := fragment.FilePath
		hasPathInput := pathInput != ""
		hasCommitInput := commitInput != ""

		// ---- commit field ----
		commitVerdict := FieldVerdict{Field: fieldCommit, ValueIndex: -1}
		if len(a.Commits) == 0 {
			commitVerdict.Status = statusNotDeclared
		} else if !hasCommitInput {
			commitVerdict.Status = statusNotApplicable
		} else {
			if ok, idx := a.CommitMatch(commitInput); ok {
				commitVerdict.Status = statusTrue
				commitVerdict.ValueIndex = idx
			} else {
				commitVerdict.Status = statusFalse
			}
		}

		// ---- path field ----
		pathVerdict := FieldVerdict{Field: fieldPath, ValueIndex: -1}
		if len(a.Paths) == 0 {
			pathVerdict.Status = statusNotDeclared
		} else if !hasPathInput {
			pathVerdict.Status = statusNotApplicable
		} else {
			matched := false
			if ok, idx := a.PathMatch(pathInput); ok {
				pathVerdict.Status = statusTrue
				pathVerdict.ValueIndex = idx
				matched = true
			}
			if !matched && fragment.WindowsFilePath != "" {
				if ok, idx := a.PathMatch(fragment.WindowsFilePath); ok {
					pathVerdict.Status = statusTrue
					pathVerdict.ValueIndex = idx
				}
			}
			if pathVerdict.Status == "" {
				pathVerdict.Status = statusFalse
			}
		}

		// ---- regex field (with explicit projection) ----
		projection := projectionSecret
		switch a.RegexTarget {
		case "match":
			projection = projectionMatch
		case "line":
			projection = projectionLine
		}
		var projectionInput string
		if finding != nil {
			switch projection {
			case projectionMatch:
				projectionInput = finding.Match
			case projectionLine:
				projectionInput = currentLine
			default:
				projectionInput = finding.Secret
			}
		}
		regexVerdict := FieldVerdict{Field: fieldRegex, ValueIndex: -1, Projection: projection}
		if len(a.Regexes) == 0 {
			regexVerdict.Status = statusNotDeclared
		} else if projectionInput == "" {
			// Declared but no candidate input. The conflict is only raised
			// once the stage scoping confirms the field participates in the
			// merge (see below); at file scope content fields are simply
			// not-applicable by design.
			regexVerdict.Status = statusNotApplicable
		} else {
			if ok, idx := a.RegexMatch(projectionInput); ok {
				regexVerdict.Status = statusTrue
				regexVerdict.ValueIndex = idx
			} else {
				regexVerdict.Status = statusFalse
			}
		}

		// ---- stopword field (always targets the secret) ----
		stopwordVerdict := FieldVerdict{Field: fieldStopword, ValueIndex: -1}
		var secretInput string
		if finding != nil {
			secretInput = finding.Secret
		}
		if len(a.StopWords) == 0 {
			stopwordVerdict.Status = statusNotDeclared
		} else if secretInput == "" {
			stopwordVerdict.Status = statusNotApplicable
		} else {
			if ok, idx := a.StopWordMatch(secretInput); ok {
				stopwordVerdict.Status = statusTrue
				stopwordVerdict.ValueIndex = idx
			} else {
				stopwordVerdict.Status = statusFalse
			}
		}

		// Stage scoping mirrors the legacy merge exactly.
		switch stage {
		case stageFile:
			commitVerdict.InMerge = commitVerdict.Status != statusNotDeclared
			pathVerdict.InMerge = pathVerdict.Status != statusNotDeclared
			regexVerdict.InMerge = false
			stopwordVerdict.InMerge = false
			if regexVerdict.Status != statusNotDeclared {
				regexVerdict.Status = statusNotApplicable
			}
			if stopwordVerdict.Status != statusNotDeclared {
				stopwordVerdict.Status = statusNotApplicable
			}
		case stageFinding:
			commitVerdict.InMerge = a.MatchCondition == config.AllowlistMatchAnd && commitVerdict.Status != statusNotDeclared
			pathVerdict.InMerge = a.MatchCondition == config.AllowlistMatchAnd && pathVerdict.Status != statusNotDeclared
			regexVerdict.InMerge = regexVerdict.Status != statusNotDeclared
			stopwordVerdict.InMerge = stopwordVerdict.Status != statusNotDeclared
			if a.MatchCondition == config.AllowlistMatchOr {
				if commitVerdict.Status != statusNotDeclared {
					commitVerdict.InMerge = false
				}
				if pathVerdict.Status != statusNotDeclared {
					pathVerdict.InMerge = false
				}
			}
		}

		v.Fields = []FieldVerdict{commitVerdict, pathVerdict, regexVerdict, stopwordVerdict}
		// A declared, merge-participating field whose candidate input is
		// missing is a structural conflict rather than a plain false. At
		// file scope the content fields are deliberately outside the merge.
		if stage == stageFinding {
			for _, fv := range v.Fields {
				if fv.InMerge && fv.Status == statusNotApplicable {
					v.ConflictCodes = append(v.ConflictCodes, config.ConflictFieldUnavailable)
				}
			}
		}
		v.Matched = anyFieldTrue(v.Fields)
		v.Suppresses = legacyMerge(stage, a, commitVerdict, pathVerdict, regexVerdict, stopwordVerdict)
		verdicts = append(verdicts, v)
		if v.Suppresses {
			hits = append(hits, v)
		}
	}

	// Deterministic total order over every hit: layer priority, then
	// declaration ordinal. Independent of map iteration or rule traversal.
	sort.SliceStable(hits, func(i, j int) bool {
		li, lj := layerRank(hits[i].Layer), layerRank(hits[j].Layer)
		if li != lj {
			return li < lj
		}
		return hits[i].Ordinal < hits[j].Ordinal
	})

	out := evaluation{verdicts: verdicts, hits: hits}
	if len(hits) > 0 {
		out.suppresses = true
		hit := hits[0]
		out.adjudicator = &hit
	}
	return out
}

// legacyMerge reproduces the exact historical suppression decision for one
// allowlist at one stage, including its quirks (OR lists at file scope only
// consider commit/path; AND lists declaring content fields never file-skip;
// unavailable inputs participate as false, which the vector flags separately
// as not-applicable).
func legacyMerge(stage string, a *config.Allowlist, commit, path, regex, stopword FieldVerdict) bool {
	boolVal := func(f FieldVerdict) bool { return f.Status == statusTrue }

	if stage == stageFile {
		if a.MatchCondition == config.AllowlistMatchAnd {
			// Historical behavior: an AND allowlist declaring regex/stopword
			// cannot be resolved at file scope and is skipped.
			if regex.Status != statusNotDeclared || stopword.Status != statusNotDeclared {
				return false
			}
			var checks []bool
			if commit.Status != statusNotDeclared {
				checks = append(checks, boolVal(commit))
			}
			if path.Status != statusNotDeclared {
				checks = append(checks, boolVal(path))
			}
			return allTrue(checks)
		}
		return boolVal(commit) || boolVal(path)
	}

	// Finding stage.
	if a.MatchCondition == config.AllowlistMatchAnd {
		var checks []bool
		if commit.Status != statusNotDeclared {
			checks = append(checks, boolVal(commit))
		}
		if path.Status != statusNotDeclared {
			checks = append(checks, boolVal(path))
		}
		if regex.Status != statusNotDeclared {
			checks = append(checks, boolVal(regex))
		}
		if stopword.Status != statusNotDeclared {
			checks = append(checks, boolVal(stopword))
		}
		return allTrue(checks)
	}
	return boolVal(regex) || boolVal(stopword)
}

func anyFieldTrue(fields []FieldVerdict) bool {
	for _, f := range fields {
		if f.Status == statusTrue {
			return true
		}
	}
	return false
}

// layerRank defines the adjudication priority total order. Smaller rank
// wins as the adjudicator. The order is rule > global > extension > builtin:
// the allowlist closest to the rule takes precedence, which matches the
// historical evaluation order (rule list set is checked after, and therefore
// wins ties over, the global list set).
func layerRank(layer string) int {
	switch layer {
	case "rule":
		return 1
	case "global":
		return 2
	case "extension":
		return 3
	case "builtin":
		return 4
	default:
		return 9
	}
}

// adjudicationPosition renders the layer-scoped, declaration-recoverable
// position of the allowlist.
func adjudicationPosition(a *config.Allowlist) string {
	if a.Stamp == nil {
		return "ad-hoc"
	}
	return a.Stamp.Layer.String() + "/" + a.Stamp.Kind + "[" + itoa(a.Stamp.Index) + "]"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// ---- recording ----

func (ad *Adjudicator) noteConflict(c config.AllowlistConflict) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	ad.conflicts[conflictKey(c)] = c
}

func (ad *Adjudicator) countSuppression(ev evaluation) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	for _, v := range ev.verdicts {
		ad.evaluatedByLayer[v.Layer]++
		if v.Matched {
			ad.matched[v.AllowlistID] = struct{}{}
		}
	}
	if ev.adjudicator != nil {
		ad.suppressedByLayer[ev.adjudicator.Layer]++
	}
}

func (ad *Adjudicator) countEvaluation(ev evaluation) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	for _, v := range ev.verdicts {
		ad.evaluatedByLayer[v.Layer]++
		if v.Matched {
			ad.matched[v.AllowlistID] = struct{}{}
		}
	}
}

func (ad *Adjudicator) addRecord(r Record) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	ad.records = append(ad.records, r)
}

func (ad *Adjudicator) noteInlineSuppression() {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	ad.inlineSuppressed++
}

func (ad *Adjudicator) noteGitleaksIgnoreSuppression() {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	ad.ignoreSuppressed++
}

func (ad *Adjudicator) noteBaselineSuppression() {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	ad.baselineSuppressed++
}

// candidateRef builds a content-free candidate reference.
func candidateRef(ruleID string, fragment Fragment, finding *report.Finding) CandidateRef {
	ref := CandidateRef{RuleID: ruleID, File: fragment.FilePath, Commit: fragment.CommitSHA}
	if finding != nil {
		ref.StartLine = finding.StartLine
		ref.EndLine = finding.EndLine
		ref.StartColumn = finding.StartColumn
		ref.EndColumn = finding.EndColumn
	}
	return ref
}

// finalize renders the deterministic report. Records are sorted by stable
// candidate coordinates so two identical runs are byte-identical.
func (ad *Adjudicator) finalize() AdjudicationReport {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	records := append([]Record(nil), ad.records...)
	sort.SliceStable(records, func(i, j int) bool {
		a, b := records[i].Candidate, records[j].Candidate
		if a.Commit != b.Commit {
			return a.Commit < b.Commit
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.StartLine != b.StartLine {
			return a.StartLine < b.StartLine
		}
		if a.StartColumn != b.StartColumn {
			return a.StartColumn < b.StartColumn
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return records[i].Stage < records[j].Stage
	})

	// Per-layer no-hit counts.
	noHitByLayer := map[string]int{}
	layerOf := map[string]string{}
	for id, al := range ad.inventory {
		layer := "ad-hoc"
		if al.Stamp != nil {
			layer = al.Stamp.Layer.String()
		}
		layerOf[id] = layer
		if _, ok := ad.matched[id]; !ok {
			noHitByLayer[layer]++
		}
	}

	conflictCounts := map[string]int{}
	conflicts := make([]config.AllowlistConflict, 0, len(ad.conflicts))
	for _, c := range ad.conflicts {
		conflicts = append(conflicts, c)
		conflictCounts[c.Code]++
		for _, layer := range c.Layers {
			_ = layer
		}
	}
	sort.Slice(conflicts, func(i, j int) bool {
		if conflicts[i].Code != conflicts[j].Code {
			return conflicts[i].Code < conflicts[j].Code
		}
		return joinIDs(conflicts[i].AllowlistIDs) < joinIDs(conflicts[j].AllowlistIDs)
	})

	// Per-layer conflict attribution.
	conflictsByLayer := map[string]int{}
	for _, c := range conflicts {
		seen := map[string]struct{}{}
		for _, layer := range c.Layers {
			if layer == "" {
				continue
			}
			if _, ok := seen[layer]; ok {
				continue
			}
			seen[layer] = struct{}{}
			conflictsByLayer[layer]++
		}
	}

	layers := []string{"builtin", "extension", "global", "rule"}
	ledgers := make([]LayerLedger, 0, len(layers))
	suppressed, retained := 0, 0
	for _, layer := range layers {
		ledgers = append(ledgers, LayerLedger{
			Layer:           layer,
			Suppressed:      ad.suppressedByLayer[layer],
			Evaluated:       ad.evaluatedByLayer[layer],
			NoHitAllowlists: noHitByLayer[layer],
			Conflicts:       conflictsByLayer[layer],
		})
	}
	for _, r := range records {
		if r.Decision == "suppressed" {
			suppressed++
		} else {
			retained++
		}
	}

	return AdjudicationReport{
		Version: adjudicationVersion,
		Summary: Summary{
			TotalCandidates:          len(records),
			Suppressed:               suppressed,
			Retained:                 retained,
			ByLayer:                  ledgers,
			ConflictCounts:           conflictCounts,
			InlineCommentSuppressed:  ad.inlineSuppressed,
			GitleaksIgnoreSuppressed: ad.ignoreSuppressed,
			BaselineSuppressed:       ad.baselineSuppressed,
		},
		Conflicts: conflicts,
		Records:   records,
	}
}
