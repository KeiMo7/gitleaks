package detect

import (
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

// locationKey identifies a single physical match position. Two findings
// with the same key describe different rules firing on the same text.
type locationKey struct {
	file        string
	commit      string
	startLine   int
	startColumn int
	endLine     int
	endColumn   int
}

func keyOf(f report.Finding) locationKey {
	return locationKey{
		file:        f.File,
		commit:      f.Commit,
		startLine:   f.StartLine,
		startColumn: f.StartColumn,
		endLine:     f.EndLine,
		endColumn:   f.EndColumn,
	}
}

// resolvePriorities enforces the declared priority for rules that fire on
// the same location. For each location exactly one finding survives as the
// conclusion; the other matches are retained on the winner as
// SupportingFindings, preserving their own rule and priority provenance.
//
// The winner is chosen by:
//  1. the highest explicit Rule.Priority;
//  2. then the rule's stable declaration order (earlier wins), which is
//     deterministic and independent of Go map iteration.
//
// When no rule at a location declares a priority, the historical
// declaration-order winner is unchanged and no supporting entries are
// attached, keeping single-rule output byte-identical.
func resolvePriorities(findings []report.Finding, rules map[string]config.Rule) []report.Finding {
	if len(findings) <= 1 {
		return findings
	}

	groups := make(map[locationKey][]int)
	order := make([]locationKey, 0, len(findings))
	for i, f := range findings {
		k := keyOf(f)
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] = append(groups[k], i)
	}

	winners := make(map[locationKey]int, len(order))
	for k, indices := range groups {
		win := indices[0]
		for _, idx := range indices[1:] {
			if outranks(findings[idx], findings[win], rules) {
				win = idx
			}
		}
		winners[k] = win
	}

	out := make([]report.Finding, 0, len(order))
	for _, k := range order {
		indices := groups[k]
		winIdx := winners[k]
		winner := findings[winIdx]
		winRule, hasRule := rules[winner.RuleID]
		if hasRule {
			winner.RulePriority = winRule.Priority
			winner.RulePrioritySource = winRule.PrioritySource
		}

		if len(indices) > 1 {
			for _, idx := range indices {
				if idx == winIdx {
					continue
				}
				loser := findings[idx]
				support := &report.SupportingFinding{
					RuleID:      loser.RuleID,
					StartLine:   loser.StartLine,
					EndLine:     loser.EndLine,
					StartColumn: loser.StartColumn,
					EndColumn:   loser.EndColumn,
					Match:       loser.Match,
					Secret:      loser.Secret,
				}
				if r, ok := rules[loser.RuleID]; ok {
					support.RulePriority = r.Priority
					support.RulePrioritySource = r.PrioritySource
				}
				winner.SupportingFindings = append(winner.SupportingFindings, support)
			}
		}
		out = append(out, winner)
	}
	return out
}

// outranks reports whether finding a should beat finding b for the same
// location. Explicit priority wins first; ties and "no priority" cases
// fall back to declaration order, then rule ID for total determinism.
func outranks(a, b report.Finding, rules map[string]config.Rule) bool {
	ra, oa := rules[a.RuleID]
	rb, ob := rules[b.RuleID]
	switch {
	case oa && ob && ra.Priority != rb.Priority:
		return ra.Priority > rb.Priority
	case oa && !ob:
		return true
	case !oa && ob:
		return false
	case oa && ob && ra.Order() != rb.Order():
		return ra.Order() < rb.Order()
	default:
		return a.RuleID < b.RuleID
	}
}
