package detect

import (
	"encoding/json"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/zricethezav/gitleaks/v8/report"
)

// This file contains the structural baseline identity layer.
//
// A baseline entry is considered the same finding when its stable,
// format-independent coordinates agree:
//
//	rule identifier + location (normalized file and line) + visible content.
//
// Presentation-only metadata (descriptions, tags, entropy float noise,
// date encodings, author/message fields, ...) never participates.

// Relation is the tri-state result of comparing a scanned finding with a
// baseline entry.
type Relation int

const (
	// Distinct means the two entries are provably different findings.
	Distinct Relation = iota
	// Same means the two entries describe the same evaluated finding.
	Same
	// Undecidable means the baseline entry lacks the coordinates required
	// to safely decide; it must never be treated as a wildcard match.
	Undecidable
)

// Decidable reports whether an entry carries the minimum coordinates required
// for structural matching: a rule identifier plus a location. A file path is
// preferred, but rule + start line is accepted as well so file-less inputs
// such as `gitleaks stdin` reports remain usable; missing fields may also be
// recovered from a gitleaks fingerprint.
func Decidable(f report.Finding) bool {
	hasRule := strings.TrimSpace(f.RuleID) != ""
	hasFile := strings.TrimSpace(f.File) != ""

	// Direct coordinates: a rule plus either a file or a line.
	if hasRule && (hasFile || f.StartLine > 0) {
		return true
	}

	// Coordinates recoverable from a gitleaks fingerprint.
	if fp, ok := parseFingerprint(f.Fingerprint); ok &&
		strings.TrimSpace(fp.ruleID) != "" &&
		(strings.TrimSpace(fp.file) != "" || fp.line > 0) {
		return true
	}
	return false
}

// Equivalent reports the structural Relation between a freshly scanned
// finding and a baseline entry. redact is the detector's redaction
// percentage; it is retained for callers that mirror IsNew's contract, the
// structural comparison itself infers masking from the values.
func Equivalent(finding report.Finding, baseline report.Finding, redact uint) Relation {
	if !Decidable(baseline) {
		return Undecidable
	}
	if structuralEqual(finding, baseline) {
		return Same
	}
	return Distinct
}

// structuralEqual implements the overlay matching layer. It never compares
// presentation-only fields.
func structuralEqual(fIn, bIn report.Finding) bool {
	// Fingerprints are used to FILL missing coordinates (fingerprint-only
	// entries, sparser cross-format reports); they never override explicit
	// fields and an identical raw fingerprint is not enough on its own.
	f := fIn
	b := bIn
	enrichFromFingerprint(&f)
	enrichFromFingerprint(&b)

	if f.RuleID == "" || b.RuleID == "" || f.RuleID != b.RuleID {
		return false
	}

	// Commit metadata is allowed to be missing on either side (directory
	// scans vs. git scans, stripped reports). When both sides record a
	// commit and disagree, however, keep today's distinction.
	if f.Commit != "" && b.Commit != "" && f.Commit != b.Commit {
		return false
	}

	if !locationEqual(f, b) {
		return false
	}

	if !contentEqual(f, b) {
		return false
	}

	return true
}

// locationEqual compares normalized paths (including symlink/alternate path
// fields) and line/column coordinates.
func locationEqual(f report.Finding, b report.Finding) bool {
	fp := nonEmptyPaths(f.File, f.SymlinkFile)
	bp := nonEmptyPaths(b.File, b.SymlinkFile)

	switch {
	case len(fp) > 0 && len(bp) > 0:
		if !pathSlicesIntersect(fp, bp) {
			return false
		}
	case len(fp) == 0 && len(bp) == 0:
		// Both file-less (e.g. stdin findings): nothing to compare.
	default:
		// Exactly one side records a file. A file-less baseline must not
		// match arbitrary on-disk findings (and vice versa).
		return false
	}

	// StartLine is the fingerprint anchor and must match exactly. Zero is a
	// legitimate coordinate (e.g. path-only findings), so it is not treated
	// as "unknown". This prevents matching every line of the same rule/file.
	if f.StartLine != b.StartLine {
		return false
	}

	// End line and columns are only enforced when both reports carry a
	// concrete, non-zero value. Missing coordinates in sparser formats must
	// not invalidate an otherwise identical entry.
	if !coordinateMatches(f.EndLine, b.EndLine) ||
		!coordinateMatches(f.StartColumn, b.StartColumn) ||
		!coordinateMatches(f.EndColumn, b.EndColumn) {
		return false
	}

	return true
}

func nonEmptyPaths(ps ...string) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return out
}

func pathSlicesIntersect(as, bs []string) bool {
	for _, a := range as {
		for _, b := range bs {
			if sameFilePath(a, b) {
				return true
			}
		}
	}
	return false
}

func coordinateMatches(a, b int) bool {
	if a == 0 || b == 0 {
		return true
	}
	return a == b
}

// sameFilePath compares two path expressions independent of their textual
// shape: relative, "./"-prefixed, absolute, slash/backslash separated,
// added/changed root prefixes and best-effort symlink/real-target forms are
// all accepted.
//
// The rule is segment based: the shorter segment sequence must be a trailing
// suffix of the longer one, so an added directory prefix never breaks a
// match while different file names still do. Line coordinates are enforced
// separately by the caller, which prevents matching every occurrence of the
// same rule/file.
func sameFilePath(a, b string) bool {
	na := normalizePath(a)
	nb := normalizePath(b)
	if na == "" || nb == "" {
		// An unknown location must never intersect another location.
		return false
	}
	if na == nb {
		return true
	}

	sa := pathSegments(na)
	sb := pathSegments(nb)
	if len(sa) > 0 && len(sb) > 0 {
		short, long := sa, sb
		if len(short) > len(long) {
			short, long = long, short
		}
		if len(short) > 0 && len(short) <= len(long) &&
			equalStringSlices(short, long[len(long)-len(short):]) {
			return true
		}

		// Root migration with a differently named leading root: accept when
		// at least the parent directory plus file name agree.
		common := 0
		for common < len(sa) && common < len(sb) &&
			sa[len(sa)-1-common] == sb[len(sb)-1-common] {
			common++
		}
		if common >= 2 {
			return true
		}
	}

	// Best-effort filesystem identity for symlink <-> target pairs. Results
	// are cached because matching runs on a hot path.
	ra := evalSymlinkCached(a)
	rb := evalSymlinkCached(b)
	if ra != "" && rb != "" && normalizePath(ra) == normalizePath(rb) {
		return true
	}
	return false
}

func pathSegments(p string) []string {
	return strings.Split(strings.TrimPrefix(p, "/"), "/")
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// normalizePath canonicalizes a path for comparison without touching the
// filesystem: backslashes become separators, Windows drive/UNC prefixes are
// neutralized and ".", ".." and duplicate separators are resolved.
func normalizePath(p string) string {
	if p == "" {
		return ""
	}
	s := strings.TrimSpace(p)
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "\\", "/")

	// Windows drive prefix: C:/... or C:...
	if len(s) >= 2 && s[1] == ':' && ((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z')) {
		s = s[2:]
		if s != "" && s[0] != '/' {
			s = "/" + s
		}
	}

	s = path.Clean(s)
	if s == "." {
		return ""
	}
	return s
}

var evalSymlinkCache sync.Map // map[string]string

// evalSymlinkCached resolves symlinks once per observed path. It returns ""
// when the path cannot be resolved (historical baselines often reference
// files that no longer exist), which simply opts out of filesystem identity.
func evalSymlinkCached(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if v, ok := evalSymlinkCache.Load(p); ok {
		return v.(string)
	}
	resolved := ""
	if r, err := filepath.EvalSymlinks(p); err == nil {
		resolved = r
	}
	evalSymlinkCache.Store(p, resolved)
	return resolved
}

// --- content / masking -----------------------------------------------------

type maskKind int

const (
	maskPlain maskKind = iota
	maskFull
	maskPartial
)

// describeMask classifies how a content value has been obscured and returns
// its visible prefix (for plain values that is the whole value).
func describeMask(v string) (maskKind, string) {
	if v == "" {
		return maskPlain, ""
	}

	first := -1
	tokenLen := 0
	consider := func(idx, n int) {
		if idx < 0 {
			return
		}
		if first == -1 || idx < first {
			first = idx
			tokenLen = n
		}
	}

	if idx := strings.Index(v, redactedToken); idx >= 0 {
		consider(idx, len(redactedToken))
	}
	if idx := strings.Index(v, "..."); idx >= 0 {
		consider(idx, 3)
	}
	if idx := firstStarRun(v); idx >= 0 {
		consider(idx, 2)
	}

	if first == -1 {
		return maskPlain, v
	}

	prefix := v[:first]
	// Nothing visible before the mask marker means the whole value is
	// effectively obscured.
	if strings.TrimSpace(prefix) == "" {
		return maskFull, ""
	}
	_ = tokenLen
	return maskPartial, prefix
}

const redactedToken = "REDACTED"

// firstStarRun returns the index of the first run of at least two '*'
// characters. A single star commonly occurs in real secrets and is not
// treated as masking.
func firstStarRun(v string) int {
	run := 0
	start := -1
	for i, r := range v {
		if r == '*' {
			if run == 0 {
				start = i
			}
			run++
			if run >= 2 {
				return start
			}
		} else {
			run = 0
			start = -1
		}
	}
	return -1
}

// contentEqual compares the visible credential/match content in a way that
// respects masking:
//
//   - fully obscured baseline  -> rule + location decide;
//   - partially obscured       -> shared visible prefix decides;
//   - unobscured values        -> exact equality is required.
func contentEqual(f, b report.Finding) bool {
	return fieldContentEqual(f.Secret, b.Secret) &&
		fieldContentEqual(f.Match, b.Match)
}

func fieldContentEqual(live, baseline string) bool {
	// Missing content on either side is "no information", not a mismatch.
	if live == "" || baseline == "" {
		return true
	}

	lm, lp := describeMask(live)
	bm, bp := describeMask(baseline)

	if lm == maskFull || bm == maskFull {
		return true
	}

	if lm == maskPlain && bm == maskPlain {
		return live == baseline
	}

	// At least one side is partially masked. Both visible prefixes must
	// agree over the shorter visible length.
	if lp == "" || bp == "" {
		return true
	}
	if len(lp) <= len(bp) {
		return strings.HasPrefix(bp, lp)
	}
	return strings.HasPrefix(lp, bp)
}

// --- fingerprints ----------------------------------------------------------

type parsedFingerprint struct {
	commit string
	file   string
	ruleID string
	line   int
}

// parseFingerprint decodes the documented gitleaks fingerprint shapes:
//
//	file:rule-id:line
//	commit:file:rule-id:line
//
// It is deliberately conservative and never returns secret material.
func parseFingerprint(fp string) (parsedFingerprint, bool) {
	var p parsedFingerprint
	if fp == "" {
		return p, false
	}

	lastColon := strings.LastIndex(fp, ":")
	if lastColon < 0 {
		return p, false
	}
	line, err := strconv.Atoi(fp[lastColon+1:])
	if err != nil {
		return p, false
	}
	p.line = line
	rest := fp[:lastColon]

	ruleColon := strings.LastIndex(rest, ":")
	if ruleColon < 0 {
		return p, false
	}
	p.ruleID = rest[ruleColon+1:]
	rest = rest[:ruleColon]

	firstColon := strings.Index(rest, ":")
	if firstColon >= 0 && looksLikeCommit(rest[:firstColon]) {
		p.commit = rest[:firstColon]
		p.file = rest[firstColon+1:]
	} else {
		p.file = rest
	}

	if p.ruleID == "" || p.file == "" {
		return p, false
	}
	return p, true
}

func looksLikeCommit(s string) bool {
	if len(s) < 7 || len(s) > 40 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// --- merge / dedupe --------------------------------------------------------

// MergeBaselines folds any number of baseline slices into one deterministic,
// order-independent set. Duplicate entries collapse to a single
// representative; when duplicates carry different amounts of detail the
// richest record is retained for display.
func MergeBaselines(groups ...[]report.Finding) []report.Finding {
	var all []report.Finding
	for _, g := range groups {
		all = append(all, g...)
	}

	type bucket struct {
		rep report.Finding
	}
	// Keys are canonical structural coordinates; use a map then emit in a
	// stable order.
	members := map[string]*bucket{}
	var undecidable []report.Finding

	for _, f := range all {
		key, ok := canonicalKey(f)
		if !ok {
			// Preserve undecidable entries separately; they can never match
			// via the structural layer and remain observable to callers.
			undecidable = append(undecidable, f)
			continue
		}
		if cur, exists := members[key]; exists {
			cur.rep = combineRepresentatives(cur.rep, f)
			continue
		}
		members[key] = &bucket{rep: f}
	}

	keys := make([]string, 0, len(members))
	for k := range members {
		keys = append(keys, k)
	}
	// Sorting by key makes the folded baseline independent of input order.
	sort.Strings(keys)

	out := make([]report.Finding, 0, len(keys)+len(undecidable))
	for _, k := range keys {
		out = append(out, members[k].rep)
	}
	// Undecidable entries are appended in a stable order too.
	sort.SliceStable(undecidable, func(i, j int) bool {
		return findingLess(undecidable[i], undecidable[j])
	})
	out = append(out, undecidable...)
	return out
}

func findingLess(a, b report.Finding) bool {
	if a.RuleID != b.RuleID {
		return a.RuleID < b.RuleID
	}
	if a.File != b.File {
		return a.File < b.File
	}
	return a.StartLine < b.StartLine
}

func canonicalKey(f report.Finding) (string, bool) {
	if !Decidable(f) {
		return "", false
	}
	file := normalizePath(f.File)
	if file == "" {
		if fp, ok := parseFingerprint(f.Fingerprint); ok {
			file = normalizePath(fp.file)
		}
	}
	return strings.Join([]string{
		f.RuleID,
		file,
		strconv.Itoa(f.StartLine),
	}, "\x00"), true
}

// richness scores how much displayable information an entry carries, so
// cross-format duplicates keep the most informative representative.
func richness(f report.Finding) int {
	n := 0
	for _, v := range []string{
		f.Description, f.Match, f.Secret, f.Commit, f.Author,
		f.Email, f.Date, f.Message, f.Fingerprint, f.Link, f.SymlinkFile,
	} {
		if v != "" {
			n += len(v)
		}
	}
	n += len(f.Tags) * 4
	if f.EndLine != 0 {
		n++
	}
	if f.StartColumn != 0 {
		n++
	}
	if f.EndColumn != 0 {
		n++
	}
	return n
}

// combineRepresentatives merges two entries known to be the same baseline
// item into the most informative, order-independent representative.
func combineRepresentatives(a, b report.Finding) report.Finding {
	primary, secondary := a, b
	switch {
	case richness(b) > richness(a):
		primary, secondary = b, a
	case richness(b) == richness(a) && stableFindingKey(b) < stableFindingKey(a):
		primary, secondary = b, a
	}

	if primary.Description == "" {
		primary.Description = secondary.Description
	}
	if primary.Match == "" {
		primary.Match = secondary.Match
	}
	if primary.Secret == "" {
		primary.Secret = secondary.Secret
	}
	if primary.SymlinkFile == "" {
		primary.SymlinkFile = secondary.SymlinkFile
	}
	if primary.Commit == "" {
		primary.Commit = secondary.Commit
	}
	if primary.Author == "" {
		primary.Author = secondary.Author
	}
	if primary.Email == "" {
		primary.Email = secondary.Email
	}
	if primary.Date == "" {
		primary.Date = secondary.Date
	}
	if primary.Message == "" {
		primary.Message = secondary.Message
	}
	if primary.Fingerprint == "" {
		primary.Fingerprint = secondary.Fingerprint
	}
	if primary.Link == "" {
		primary.Link = secondary.Link
	}
	if primary.Entropy == 0 {
		primary.Entropy = secondary.Entropy
	}
	if len(primary.Tags) == 0 {
		primary.Tags = secondary.Tags
	}
	if primary.EndLine == 0 {
		primary.EndLine = secondary.EndLine
	}
	if primary.StartColumn == 0 {
		primary.StartColumn = secondary.StartColumn
	}
	if primary.EndColumn == 0 {
		primary.EndColumn = secondary.EndColumn
	}
	return primary
}

// stableFindingKey provides a deterministic tie-break independent of input
// order. It never affects matching.
func stableFindingKey(f report.Finding) string {
	b, err := json.Marshal(f)
	if err != nil {
		return f.RuleID + "\x00" + f.File
	}
	return string(b)
}
