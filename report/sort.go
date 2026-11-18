package report

import "sort"

// SortFindings orders findings deterministically so repeated runs with the
// same input produce byte-identical reports. Incremental scans visit files
// serially, but this also guards against future concurrency changes.
func SortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
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
		if a.EndLine != b.EndLine {
			return a.EndLine < b.EndLine
		}
		if a.EndColumn != b.EndColumn {
			return a.EndColumn < b.EndColumn
		}
		return a.RuleID < b.RuleID
	})
}
