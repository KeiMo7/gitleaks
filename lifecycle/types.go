// Package lifecycle derives a per-secret lifecycle view (first/last seen,
// current use, ref membership) from gitleaks findings.
//
// Findings may number in the millions, so occurrence records are written to a
// disk-backed spool and grouped with an external merge sort. Only per-secret
// summaries are held in memory; every raw location is streamed to the report.
package lifecycle

import "time"

// Kind describes the scan source.
type Kind string

const (
	KindGit       Kind = "git"
	KindDirectory Kind = "directory"
	KindStdin     Kind = "stdin"
	// KindDiff covers pre-commit and staged scans: a patch was scanned, but
	// no history is available, so conclusions are "no-history".
	KindDiff Kind = "diff"
)

// Status is the lifecycle conclusion for one secret/rule pair.
//
//   - "in-use": the secret is present in the current state of the default
//     branch.
//   - "not-in-use": history was complete and the secret is absent from the
//     default branch tip. It may still live on an unmerged branch or tag;
//     see Refs.
//   - "unknown": history was incomplete (shallow clone, replaced refs,
//     unreadable objects) so absence cannot be asserted.
//   - "no-history": the scan had no git history (directory or stdin scan).
type Status string

const (
	StatusInUse     Status = "in-use"
	StatusNotInUse  Status = "not-in-use"
	StatusUnknown   Status = "unknown"
	StatusNoHistory Status = "no-history"
)

// Occurrence is one secret hit at one location. It is the only record type
// written to the spool.
type Occurrence struct {
	SecretID string
	RuleID   string
	Commit   string
	Date     string // RFC3339, UTC
	File     string

	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
}

// Seen marks the first or last commit a secret was observed in.
type Seen struct {
	Commit string `json:"Commit"`
	Date   string `json:"Date"`
}

// Ref is one branch or tag that contains at least one occurrence.
type Ref struct {
	Name   string `json:"Name"`
	Type   string `json:"Type"`   // "branch" or "tag"
	Merged bool   `json:"Merged"` // tip is reachable from the default branch tip
	Tip    string `json:"Tip"`
}

// Info is the compact lifecycle summary attached to individual findings. The
// full list, including every location, is written to the lifecycle report.
type Info struct {
	Status    Status `json:"Status"`
	InUse     *bool  `json:"InUse,omitempty"`
	FirstSeen *Seen  `json:"FirstSeen,omitempty"`
	LastSeen  *Seen  `json:"LastSeen,omitempty"`
	Commits   int    `json:"Commits"`
	Files     int    `json:"Files"`
	// BranchCount and TagCount summarize membership; the full per-ref list
	// with merge state lives in the lifecycle report to keep this compact.
	BranchCount        int  `json:"BranchCount"`
	TagCount           int  `json:"TagCount"`
	MergedBranches     int  `json:"MergedBranches"`
	HistoricalBranches int  `json:"HistoricalBranches"`
	HistoryComplete    bool `json:"HistoryComplete"`
}

// Location is one deduplicated occurrence location.
type Location struct {
	Commit      string `json:"Commit,omitempty"`
	Date        string `json:"Date,omitempty"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	StartColumn int    `json:"StartColumn"`
	EndColumn   int    `json:"EndColumn"`
}

// Entry is one row of the lifecycle report.
type Entry struct {
	SecretID string `json:"SecretID"`
	RuleID   string `json:"RuleID"`
	Info
	// Refs lists every branch and tag containing an occurrence, with the
	// merge state of each. MergedRefs and HistoricalRefs are the same names
	// grouped by that state.
	Refs           []Ref      `json:"Refs,omitempty"`
	MergedRefs     []string   `json:"MergedRefs,omitempty"`
	HistoricalRefs []string   `json:"HistoricalRefs,omitempty"`
	Locations      []Location `json:"Locations"`
}

// RepositoryInfo describes the repository the report was produced from.
// Remote URLs are free of user information.
type RepositoryInfo struct {
	Remote          string   `json:"Remote,omitempty"`
	DefaultBranch   string   `json:"DefaultBranch,omitempty"`
	Tip             string   `json:"Tip,omitempty"`
	TipDate         string   `json:"TipDate,omitempty"`
	RootCommits     []string `json:"RootCommits,omitempty"`
	Shallow         bool     `json:"Shallow"`
	ReplacedRefs    []string `json:"ReplacedRefs,omitempty"`
	HistoryComplete bool     `json:"HistoryComplete"`
}

// Summary is the aggregate over all entries.
type Summary struct {
	Secrets     int `json:"Secrets"`
	Entries     int `json:"Entries"`
	InUse       int `json:"InUse"`
	NotInUse    int `json:"NotInUse"`
	Unknown     int `json:"Unknown"`
	NoHistory   int `json:"NoHistory"`
	Occurrences int `json:"Occurrences"`
}

// Diagnostics records degraded-but-continued conditions. Every field is a
// count or an explicit flag; a scan never fails because of these.
type Diagnostics struct {
	CommandFailures       int      `json:"CommandFailures"`
	CommandTimeouts       int      `json:"CommandTimeouts"`
	RefErrors             int      `json:"RefErrors"`
	ObjectErrors          int      `json:"ObjectErrors"`
	SkippedRefs           []string `json:"SkippedRefs,omitempty"`
	SkippedObjects        []string `json:"SkippedObjects,omitempty"`
	SkippedLargeBlobs     int      `json:"SkippedLargeBlobs"`
	SkippedLargeFragments int      `json:"SkippedLargeFragments"`
	ScanErrors            int      `json:"ScanErrors"`
	RefAnalysisLimited    bool     `json:"RefAnalysisLimited"`
	TipScanFailed         bool     `json:"TipScanFailed"`
	Notes                 []string `json:"Notes,omitempty"`
}

// Report is the lifecycle report document.
type Report struct {
	SchemaVersion int            `json:"SchemaVersion"`
	Generator     string         `json:"Generator"`
	Source        Kind           `json:"Source"`
	Repository    RepositoryInfo `json:"Repository"`
	History       HistoryInfo    `json:"History"`
	Summary       Summary        `json:"Summary"`
	Diagnostics   Diagnostics    `json:"Diagnostics"`
	Secrets       []Entry        `json:"Secrets"`
}

// HistoryInfo explains how the lifecycle conclusions were bounded.
type HistoryInfo struct {
	Complete bool     `json:"Complete"`
	Reasons  []string `json:"Reasons,omitempty"`
}

// CommandTimeout is the per-git-invocation deadline used during analysis.
const CommandTimeout = 60 * time.Second

// DefaultChunkSize is the number of occurrence records buffered in memory
// before a sorted run is flushed to disk.
const DefaultChunkSize = 50_000

// minFanIn is the smallest merge fan-in the external sort supports. It also
// bounds the number of simultaneously open run files.
const minFanIn = 64

// maxRefMergeBasePairs bounds the O(occurrenceCommits × refs) ancestry query
// strategy. Above it, ref membership is computed with one streaming rev-list
// per ref instead.
const maxRefMergeBasePairs = 50_000

// maxOccurrenceCommits bounds the occurrence-commit index used for ref
// analysis. Beyond it, ref analysis degrades explicitly rather than growing
// memory without bound.
const maxOccurrenceCommits = 2_000_000
