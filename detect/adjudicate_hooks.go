package detect

import (
	"github.com/rs/zerolog"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

// fileScope records which list set is adjudicated at file scope.
type fileScope struct {
	scopeName string // "global" or "rule"
	ruleID    string // empty for global
}

func stageFileScope(name, ruleID string) fileScope {
	return fileScope{scopeName: name, ruleID: ruleID}
}

// adjudicationEnabled reports whether structured adjudication is requested.
func (d *Detector) adjudicationEnabled() bool {
	return d.AdjudicationPath != ""
}

// ensureAdjudicator lazily constructs the adjudicator from the resolved
// configuration. Construction is cheap and happens at most once.
func (d *Detector) ensureAdjudicator() *Adjudicator {
	if d.adjudicator == nil {
		d.adjudicator = NewAdjudicator(d.Config)
	}
	return d.adjudicator
}

// adjudicateFile runs the unified adjudication at file scope, records both
// suppressed and retained vectors, and returns whether the file is skipped.
func (d *Detector) adjudicateFile(logger zerolog.Logger, fragment Fragment, allowlists []*config.Allowlist, sc fileScope) bool {
	ad := d.ensureAdjudicator()
	ev := evaluateAdjudication(fragment, nil, "", stageFile, allowlists)

	record := Record{
		Stage:     stageFile,
		Candidate: candidateRef(sc.ruleID, fragment, nil),
		Verdicts:  ev.verdicts,
	}
	if ev.suppresses {
		record.Decision = "suppressed"
		record.Reason = "file-scope allowlist match (" + sc.scopeName + " list set)"
		if ev.adjudicator != nil {
			record.Adjudicator = ev.adjudicator.AllowlistID
			record.AdjLayer = ev.adjudicator.Layer
		}
		for _, h := range ev.hits {
			record.HitIDs = append(record.HitIDs, h.AllowlistID)
		}
		ad.countSuppression(ev)
	} else {
		record.Decision = "retained"
		record.Reason = "no file-scope allowlist match (" + sc.scopeName + " list set)"
		ad.countEvaluation(ev)
	}
	ad.addRecord(record)
	ad.collectRuntimeConflicts(ev)

	if ev.suppresses {
		logger.Trace().
			Str("adjudicator", record.Adjudicator).
			Str("adjudicator-layer", record.AdjLayer).
			Int("hit-count", len(ev.hits)).
			Msg("adjudication: file suppressed")
	}
	return ev.suppresses
}

// adjudicateFinding runs the unified adjudication at finding scope, records
// both vectors, and returns whether the finding is suppressed.
func (d *Detector) adjudicateFinding(logger zerolog.Logger, finding report.Finding, fragment Fragment, currentLine string, allowlists []*config.Allowlist, scopeName, ruleID string) bool {
	ad := d.ensureAdjudicator()
	f := finding // local copy; never put secret-bearing fields into the record
	ev := evaluateAdjudication(fragment, &f, currentLine, stageFinding, allowlists)

	record := Record{
		Stage:     stageFinding,
		Candidate: candidateRef(ruleID, fragment, &f),
		Verdicts:  ev.verdicts,
	}
	if ev.suppresses {
		record.Decision = "suppressed"
		record.Reason = "finding-scope allowlist match (" + scopeName + " list set)"
		if ev.adjudicator != nil {
			record.Adjudicator = ev.adjudicator.AllowlistID
			record.AdjLayer = ev.adjudicator.Layer
		}
		for _, h := range ev.hits {
			record.HitIDs = append(record.HitIDs, h.AllowlistID)
		}
		ad.countSuppression(ev)
	} else {
		record.Decision = "retained"
		record.Reason = "no finding-scope allowlist match (" + scopeName + " list set)"
		ad.countEvaluation(ev)
	}
	ad.addRecord(record)
	ad.collectRuntimeConflicts(ev)

	if ev.suppresses {
		logger.Trace().
			Str("adjudicator", record.Adjudicator).
			Str("adjudicator-layer", record.AdjLayer).
			Int("hit-count", len(ev.hits)).
			Msg("adjudication: finding suppressed")
	}
	return ev.suppresses
}

// collectRuntimeConflicts records field-unavailability and contradiction
// conflicts observed during evaluation.
func (ad *Adjudicator) collectRuntimeConflicts(ev evaluation) {
	for _, v := range ev.verdicts {
		for _, code := range v.ConflictCodes {
			ad.noteConflict(config.AllowlistConflict{
				Code:         code,
				AllowlistIDs: []string{v.AllowlistID},
				Layers:       []string{v.Layer},
				ConfigPaths:  []string{v.ConfigPath},
				Detail:       "declared field has no usable input for the candidate",
			})
		}
	}

	// Contradiction: allowlists from DIFFERENT sources that share a true
	// field on the same candidate but reach opposite suppression verdicts.
	// Same-source allowlists with differing verdicts are ordinary layering,
	// not contradictions.
	var matching []AllowlistVerdict
	for _, v := range ev.verdicts {
		if v.Matched {
			matching = append(matching, v)
		}
	}
	if len(matching) >= 2 {
		var suppresses, retains []AllowlistVerdict
		for _, v := range matching {
			if v.Suppresses {
				suppresses = append(suppresses, v)
			} else {
				retains = append(retains, v)
			}
		}
		if len(suppresses) > 0 && len(retains) > 0 {
			var ids, layers, paths []string
			crossSource := false
			for _, s := range suppresses {
				for _, r := range retains {
					if s.sourceKey() == r.sourceKey() {
						continue
					}
					if verdictsShareTrueField(s, r) {
						crossSource = true
						ids = append(ids, s.AllowlistID, r.AllowlistID)
						layers = append(layers, s.Layer, r.Layer)
						paths = append(paths, s.ConfigPath, r.ConfigPath)
					}
				}
			}
			if crossSource {
				ad.noteConflict(config.AllowlistConflict{
					Code:         config.ConflictContradiction,
					AllowlistIDs: dedupeStrings(ids),
					Layers:       dedupeStrings(layers),
					ConfigPaths:  dedupeStrings(paths),
					Detail:       "same candidate yields opposite verdicts across sources",
				})
			}
		}
	}
}

// sourceKey distinguishes declaration sources for the contradiction rule.
func (v AllowlistVerdict) sourceKey() string {
	return v.Layer + "|" + v.ConfigPath
}

// verdictsShareTrueField reports whether two verdicts have a true value on the
// same field (and, for multi-value fields, the same declared value index).
func verdictsShareTrueField(a, b AllowlistVerdict) bool {
	for _, fa := range a.Fields {
		if fa.Status != statusTrue {
			continue
		}
		for _, fb := range b.Fields {
			if fb.Status == statusTrue && fa.Field == fb.Field && fa.ValueIndex == fb.ValueIndex {
				return true
			}
		}
	}
	return false
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// FinalizeAdjudication renders the deterministic report. It is called once at
// scan finalize.
func (d *Detector) FinalizeAdjudication() (AdjudicationReport, bool) {
	if d.adjudicator == nil {
		return AdjudicationReport{}, false
	}
	return d.adjudicator.finalize(), true
}

// CountInlineCommentSuppression records a gitleaks:allow suppression.
func (d *Detector) CountInlineCommentSuppression() {
	if d.adjudicator != nil {
		d.adjudicator.noteInlineSuppression()
	}
}

// CountGitleaksIgnoreSuppression records a .gitleaksignore suppression.
func (d *Detector) CountGitleaksIgnoreSuppression() {
	if d.adjudicator != nil {
		d.adjudicator.noteGitleaksIgnoreSuppression()
	}
}

// CountBaselineSuppression records a baseline suppression.
func (d *Detector) CountBaselineSuppression() {
	if d.adjudicator != nil {
		d.adjudicator.noteBaselineSuppression()
	}
}
