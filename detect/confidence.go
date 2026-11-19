package detect

import (
	"sort"
	"strings"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

// Stable, machine-readable reason codes. They appear verbatim in the
// ConfidenceReasons field of every finding produced by the joint engine,
// which is what makes a decision explainable.
const (
	reasonRuleNamed       = "rule:named"
	reasonRuleGeneric     = "rule:generic"
	reasonEntropyHigh     = "entropy:high"
	reasonEntropyLow      = "entropy:low"
	reasonEntropyBelow    = "entropy:below-rule-threshold"
	reasonPrefixKnown     = "prefix:known"
	reasonResourceContent = "resource:content"
	reasonResourcePath    = "resource:path"
	reasonResourceStop    = "resource:stopword"
	reasonVetoResource    = "veto:high-entropy-resource"
	reasonVetoLowScore    = "veto:below-report-threshold"
	reasonClusterMerged   = "cluster:merged-duplicate"
)

// confidenceSignals carries the raw, per-finding evidence collected at the
// point where rule matching and entropy meet. It is computed deterministically
// from the fragment content and the rule, never from scan order or global
// state, so an incremental scan and a full scan derive identical signals for
// the same file.
type confidenceSignals struct {
	genericRule          bool
	legacyRuleEntropy    float64
	entropy              float64
	hasKnownPrefix       bool
	resourceContentHits  int
	resourcePathHits     int
	resourceStopWordHits int
}

// collectSignals gathers all evidence for one rule match.
func (d *Detector) collectSignals(finding report.Finding, r config.Rule, filePath string) confidenceSignals {
	cc := d.Config.Confidence

	s := confidenceSignals{
		genericRule:       strings.Contains(strings.ToLower(r.RuleID), "generic"),
		legacyRuleEntropy: r.Entropy,
		entropy:           float64(finding.Entropy),
	}

	// Known credential prefixes rescue short, structurally credential-like
	// strings that a pure entropy gate would drop.
	lowerSecret := strings.ToLower(finding.Secret)
	for _, p := range cc.Prefixes {
		if p != "" && strings.HasPrefix(lowerSecret, strings.ToLower(p)) {
			s.hasKnownPrefix = true
			break
		}
	}

	s.resourceContentHits = countContentPatterns(cc, finding.Secret)
	s.resourcePathHits = countPathPatterns(cc, filePath)
	s.resourceStopWordHits = countStopWords(cc, lowerSecret)
	return s
}

func countContentPatterns(cc *config.ConfidenceConfig, secret string) int {
	hits := 0
	for _, re := range cc.ResourceContentRegexes() {
		if re.MatchString(secret) {
			hits++
		}
	}
	return hits
}

func countPathPatterns(cc *config.ConfidenceConfig, filePath string) int {
	if filePath == "" {
		return 0
	}
	hits := 0
	for _, re := range cc.ResourcePathRegexes() {
		if re.MatchString(filePath) {
			hits++
		}
	}
	return hits
}

func countStopWords(cc *config.ConfidenceConfig, lowerSecret string) int {
	hits := 0
	for _, w := range cc.Resource.StopWords {
		if w != "" && strings.Contains(lowerSecret, w) {
			hits++
		}
	}
	return hits
}

// confidenceDecision is the fully explained outcome of the joint decision.
type confidenceDecision struct {
	score   float64
	level   string
	reasons []string
	veto    string // empty when the finding should be reported
}

// evaluate computes the joint rule/entropy confidence for one finding.
//
// The score is an explicitly additive combination of independent signals
// (rule strength, entropy band, known prefix, resource penalties), so any
// conflict between "rule matched" and "entropy looks benign" is resolved by
// the resulting confidence rather than a logical OR. Every contributing
// signal is recorded in reasons.
func (d *Detector) evaluate(s confidenceSignals) confidenceDecision {
	cc := d.Config.Confidence
	var reasons []string

	// 1. Rule signal.
	score := 0.0
	if s.genericRule {
		score += cc.Scoring.GenericRuleBase
		reasons = append(reasons, reasonRuleGeneric)
	} else {
		score += cc.Scoring.NamedRuleBase
		reasons = append(reasons, reasonRuleNamed)
	}

	// 2. Entropy signal — replaces the legacy hard entropy gate. The rule's
	// own entropy threshold is reinterpreted as a band boundary instead of a
	// drop condition, so short prefixed credentials survive.
	switch {
	case s.entropy >= cc.Entropy.HighThreshold:
		score += cc.Scoring.EntropyHigh
		reasons = append(reasons, reasonEntropyHigh)
	case s.legacyRuleEntropy > 0 && s.entropy > s.legacyRuleEntropy:
		score += cc.Scoring.EntropyLow
		reasons = append(reasons, reasonEntropyLow)
	case s.legacyRuleEntropy > 0:
		reasons = append(reasons, reasonEntropyBelow)
	}

	// 3. Structural prefix signal.
	if s.hasKnownPrefix {
		score += cc.Scoring.KnownPrefix
		reasons = append(reasons, reasonPrefixKnown)
	}

	// 4. Resource/build-artifact signals. A single content-pattern match is
	// not, on its own, evidence of benign material (long base64 also matches
	// real secrets), so it is recorded but only penalizes the score when
	// corroborated by another resource indicator. The decisive suppression of
	// high-entropy-only resource strings is the veto below.
	resourceHits := 0
	for i := 0; i < s.resourceContentHits; i++ {
		reasons = append(reasons, reasonResourceContent)
	}
	for i := 0; i < s.resourcePathHits; i++ {
		reasons = append(reasons, reasonResourcePath)
	}
	for i := 0; i < s.resourceStopWordHits; i++ {
		reasons = append(reasons, reasonResourceStop)
	}
	resourceHits = s.resourceContentHits + s.resourcePathHits + s.resourceStopWordHits
	corroboratingHits := s.resourcePathHits + s.resourceStopWordHits
	if corroboratingHits > 0 {
		score -= cc.Scoring.ResourcePenalty * float64(corroboratingHits)
	}

	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}

	level := "medium"
	if score >= cc.Decision.HighConfidenceThreshold {
		level = "high"
	}

	// 5. Vetoes.
	// High-entropy-only hits that look like build/resource material must not
	// alarm on their own, no matter how high the entropy is. A known prefix
	// or a named (non-generic) rule means there is structural evidence beyond
	// entropy, so the veto must not fire.
	entropyIsOnlySignal := !s.hasKnownPrefix && s.genericRule
	if cc.Entropy.VetoHighEntropyOnly &&
		s.entropy >= cc.Entropy.HighThreshold &&
		entropyIsOnlySignal &&
		resourceHits >= cc.Resource.MinHits {
		return confidenceDecision{
			score: score, level: level, reasons: append(reasons, reasonVetoResource),
			veto: reasonVetoResource,
		}
	}

	if score < cc.Decision.ReportThreshold {
		return confidenceDecision{
			score: score, level: level, reasons: append(reasons, reasonVetoLowScore),
			veto: reasonVetoLowScore,
		}
	}

	return confidenceDecision{score: score, level: level, reasons: reasons}
}

// bigramJaccard returns the Jaccard similarity of the character-bigram sets
// of two strings. Identical/near-identical secrets approach 1.0. It is purely
// a function of the two inputs, hence order-independent across a scan.
func bigramJaccard(a, b string) float64 {
	setA := bigramSet(a)
	setB := bigramSet(b)
	if len(setA) == 0 || len(setB) == 0 {
		if a == b {
			return 1
		}
		return 0
	}
	intersection := 0
	for bg := range setA {
		if _, ok := setB[bg]; ok {
			intersection++
		}
	}
	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

func bigramSet(s string) map[string]struct{} {
	set := make(map[string]struct{})
	if len(s) < 2 {
		if len(s) == 1 {
			set[s] = struct{}{}
		}
		return set
	}
	for i := 0; i < len(s)-1; i++ {
		set[s[i:i+2]] = struct{}{}
	}
	return set
}

// clusterFindings merges similar hits that live in the same file (and same
// commit for git scans) into one, keeping the most confident occurrence.
// Grouping is strictly per file so an incremental single-file scan reaches
// exactly the same conclusion as a full scan for that file.
func (d *Detector) clusterFindings(findings []report.Finding) []report.Finding {
	cc := d.Config.Confidence
	if cc == nil || !cc.Cluster.Enabled || len(findings) <= 1 {
		return findings
	}

	// Deterministic input order makes the representative selection stable
	// regardless of goroutine scheduling.
	sorted := make([]report.Finding, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, findingLess(sorted))

	type group struct {
		rep     report.Finding
		members []report.Finding
	}
	var groups []*group

	for _, f := range sorted {
		placed := false
		for _, g := range groups {
			if !sameClusterScope(g.rep, f) {
				continue
			}
			if bigramJaccard(g.rep.Secret, f.Secret) >= cc.Cluster.SimilarityThreshold {
				g.members = append(g.members, f)
				// Keep the most confident member; ties resolved deterministically.
				if higherConfidence(f, g.rep) {
					g.rep = f
				}
				placed = true
				break
			}
		}
		if !placed {
			groups = append(groups, &group{rep: f, members: []report.Finding{f}})
		}
	}

	out := make([]report.Finding, 0, len(groups))
	for _, g := range groups {
		rep := g.rep
		if len(g.members) > 1 {
			rep.ConfidenceReasons = append(append([]string{}, rep.ConfidenceReasons...), reasonClusterMerged)
		}
		out = append(out, rep)
	}
	return out
}

func sameClusterScope(a, b report.Finding) bool {
	// Same file (and same commit for history scans). Line is intentionally
	// not part of the scope: the requirement is to collapse several similar
	// hits appearing at different lines inside one file into a single alert.
	return a.Commit == b.Commit && a.File == b.File
}

// higherConfidence reports whether a should win over b. Ties fall through to
// stable structural fields, guaranteeing a unique representative every time.
func higherConfidence(a, b report.Finding) bool {
	if a.ConfidenceScore != b.ConfidenceScore {
		return a.ConfidenceScore > b.ConfidenceScore
	}
	if a.RuleID != b.RuleID {
		return a.RuleID < b.RuleID
	}
	return a.Fingerprint < b.Fingerprint
}

// findingLess returns a total ordering over findings. Used both for cluster
// input stability and for the final confidence-sorted output.
func findingLess(findings []report.Finding) func(i, j int) bool {
	return func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.ConfidenceScore != b.ConfidenceScore {
			return a.ConfidenceScore > b.ConfidenceScore // high confidence first
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Commit != b.Commit {
			return a.Commit < b.Commit
		}
		if a.StartLine != b.StartLine {
			return a.StartLine < b.StartLine
		}
		if a.StartColumn != b.StartColumn {
			return a.StartColumn < b.StartColumn
		}
		return a.RuleID < b.RuleID
	}
}
