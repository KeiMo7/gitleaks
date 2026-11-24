package lifecycle

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// TipScanFunc scans one blob of the default branch tip and reports the secret
// identifiers it contains. Returning an error aborts the tip analysis, which
// downgrades conclusions to "unknown" rather than to "not-in-use".
type TipScanFunc func(ctx context.Context, path string, content []byte) ([]string, error)

// Options configures analysis.
type Options struct {
	Kind Kind
	// DefaultBranch is the branch whose tip decides "in use". When empty the
	// caller did not resolve one and conclusions become "unknown".
	DefaultBranch string
	// HistoryComplete is false when the caller restricted history, for
	// example with --log-opts.
	HistoryComplete bool
	// HistoryReasons explains a false HistoryComplete.
	HistoryReasons []string
	// FullHistory is true when the scan covered every commit reachable from
	// every ref. Default-branch conclusions are only asserted when the tip
	// could be scanned and history was complete.
	FullHistory bool
	// MaxBlobBytes bounds tip blob reads. Zero means no bound.
	MaxBlobBytes int64
	// ScanErrors and SkippedLargeFragments are degradation counters reported
	// by the detector during the scan.
	ScanErrors            int
	SkippedLargeFragments int
}

// Key identifies one lifecycle row.
type Key struct {
	SecretID string
	RuleID   string
}

// Analyzer groups spooled occurrences into lifecycle entries.
type Analyzer struct {
	repo    *Repo
	spool   *Spool
	tip     string
	tipscan TipScanFunc
	opts    Options

	tipIDs map[string]struct{}
	tipErr error
}

// NewAnalyzer creates an analyzer. repo and tipscan may be nil for scans
// without history.
func NewAnalyzer(repo *Repo, sp *Spool, tip string, tipscan TipScanFunc, opts Options) *Analyzer {
	return &Analyzer{
		repo:    repo,
		spool:   sp,
		tip:     tip,
		tipscan: tipscan,
		opts:    opts,
	}
}

// Analyze groups all spooled occurrences and streams the lifecycle document
// to w. Occurrences for one secret/rule pair are the only group held in
// memory at a time, and per-entry summaries are written to a sidecar file and
// read back one line at a time, so peak memory is bounded by the largest
// group rather than by history size or by the number of distinct secrets.
//
// It returns the per-key summaries for attaching to the primary findings;
// that map is the only structure sized by the number of distinct secret/rule
// pairs, and callers may stream findings without retaining it.
func (a *Analyzer) Analyze(ctx context.Context, w io.Writer) (*Summary, map[Key]Info, error) {
	report := &Report{
		SchemaVersion: 1,
		Generator:     "gitleaks/lifecycle",
		Source:        a.opts.Kind,
	}

	repoAvailable := a.repo != nil && a.opts.Kind == KindGit
	if repoAvailable {
		report.Repository = a.repo.RepositoryInfo(ctx, a.opts.DefaultBranch)
		if a.opts.DefaultBranch == "" {
			// Without a resolved default branch the tip conclusion is
			// unknowable; say so instead of assuming main.
			repoAvailable = false
			a.opts.HistoryReasons = append(a.opts.HistoryReasons,
				"default branch could not be determined; use --lifecycle-default-branch")
		}
		if a.tip != "" && a.tipscan != nil {
			ids, err := a.scanTip(ctx)
			if err != nil {
				a.tipErr = err
			} else {
				a.tipIDs = ids
			}
		}
		report.Diagnostics = a.repo.Diagnostics()
	}

	complete := a.opts.HistoryComplete
	reasons := append([]string(nil), a.opts.HistoryReasons...)
	if repoAvailable {
		reasons = append(reasons, historyReasons(report.Repository)...)
		if !report.Repository.HistoryComplete {
			complete = false
		}
	}
	if a.tipErr != nil {
		complete = false
		report.Diagnostics.TipScanFailed = true
		reasons = append(reasons, "default branch tip scan failed: "+a.tipErr.Error())
	}
	if !a.opts.FullHistory {
		complete = false
	}
	if !repoAvailable {
		// With no usable repository analysis, absence from the tip cannot be
		// asserted either way.
		a.tipIDs = nil
	}
	// "In use" combines the history scan with the default-branch tip. When
	// the scan was restricted (--log-opts, shallow clone, replaced refs) the
	// viewed history is not the repository's history, so neither presence nor
	// absence can be concluded from it.
	inUseKnown := repoAvailable && a.tipIDs != nil && a.tipErr == nil && a.opts.FullHistory

	report.Diagnostics.ScanErrors = a.opts.ScanErrors
	report.Diagnostics.SkippedLargeFragments = a.opts.SkippedLargeFragments
	if a.opts.ScanErrors > 0 {
		complete = false
		reasons = append(reasons, fmt.Sprintf("%d fragment(s) could not be scanned", a.opts.ScanErrors))
	}
	if a.opts.SkippedLargeFragments > 0 {
		complete = false
		reasons = append(reasons, fmt.Sprintf(
			"%d fragment(s) exceeded --max-target-megabytes and were skipped",
			a.opts.SkippedLargeFragments,
		))
	}
	if report.Diagnostics.SkippedLargeBlobs > 0 {
		// A tip blob that was not read could contain the secret, so absence
		// from the tip is not evidence of removal.
		complete = false
		reasons = append(reasons, fmt.Sprintf(
			"%d default-branch blob(s) exceeded the size limit and were not scanned",
			report.Diagnostics.SkippedLargeBlobs,
		))
	}
	if report.Diagnostics.RefErrors > 0 {
		complete = false
		reasons = append(reasons, fmt.Sprintf(
			"%d ref(s) could not be analyzed and were skipped",
			report.Diagnostics.RefErrors,
		))
	}
	if report.Diagnostics.ObjectErrors > 0 {
		complete = false
		reasons = append(reasons, fmt.Sprintf(
			"%d object(s) could not be read and were skipped",
			report.Diagnostics.ObjectErrors,
		))
	}
	if report.Diagnostics.CommandTimeouts > 0 || report.Diagnostics.CommandFailures > 0 {
		complete = false
		reasons = append(reasons, fmt.Sprintf(
			"%d git command(s) failed or timed out during analysis",
			report.Diagnostics.CommandTimeouts+report.Diagnostics.CommandFailures,
		))
	}
	report.History = HistoryInfo{Complete: complete, Reasons: dedupe(reasons)}
	report.Repository.HistoryComplete = complete

	summary := &Summary{}

	if _, err := w.Write([]byte("{\n \"SchemaVersion\": 1,\n \"Generator\": ")); err != nil {
		return nil, nil, err
	}
	if err := writeJSONValue(w, "gitleaks/lifecycle"); err != nil {
		return nil, nil, err
	}
	if _, err := w.Write([]byte(",\n \"Source\": ")); err != nil {
		return nil, nil, err
	}
	if err := writeJSONValue(w, string(a.opts.Kind)); err != nil {
		return nil, nil, err
	}
	if _, err := w.Write([]byte(",\n \"Repository\": ")); err != nil {
		return nil, nil, err
	}
	repoJSON, err := json.Marshal(report.Repository)
	if err != nil {
		return nil, nil, err
	}
	if _, err := w.Write(repoJSON); err != nil {
		return nil, nil, err
	}
	if _, err := w.Write([]byte(",\n \"History\": ")); err != nil {
		return nil, nil, err
	}
	historyJSON, err := json.Marshal(report.History)
	if err != nil {
		return nil, nil, err
	}
	if _, err := w.Write(historyJSON); err != nil {
		return nil, nil, err
	}
	if _, err := w.Write([]byte(",\n \"Diagnostics\": ")); err != nil {
		return nil, nil, err
	}
	diagJSON, err := json.Marshal(report.Diagnostics)
	if err != nil {
		return nil, nil, err
	}
	if _, err := w.Write(diagJSON); err != nil {
		return nil, nil, err
	}
	if _, err := w.Write([]byte(",\n \"Secrets\": [")); err != nil {
		return nil, nil, err
	}

	// Pass 1: emit the document body and write a compact per-entry summary to
	// a sidecar file. Keeping summaries out of memory is what bounds peak
	// memory by history size rather than by the number of distinct secrets.
	summaries := &entrySummaries{path: filepath.Join(a.spool.dir, "summaries.idx")}
	defer summaries.close()

	first := true
	err = a.spool.Group(func(group []Occurrence) error {
		entry := a.buildEntry(ctx, group, inUseKnown, complete, repoAvailable)

		summary.Entries++
		summary.Occurrences += len(entry.Locations)
		switch entry.Status {
		case StatusInUse:
			summary.InUse++
		case StatusNotInUse:
			summary.NotInUse++
		case StatusUnknown:
			summary.Unknown++
		case StatusNoHistory:
			summary.NoHistory++
		}
		if err := summaries.write(&entry); err != nil {
			return err
		}

		if !first {
			if _, err := w.Write([]byte(",")); err != nil {
				return err
			}
		}
		first = false
		if _, err := w.Write([]byte("\n  ")); err != nil {
			return err
		}
		b, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		_, err = w.Write(b)
		return err
	})
	if err != nil {
		return nil, nil, err
	}

	if err := summaries.close(); err != nil {
		return nil, nil, err
	}

	// Pass 2: read the sidecar back, one summary at a time, to produce the
	// per-finding lookup and the distinct-secret count.
	distinctIDs, infos, err := summaries.load()
	if err != nil {
		return nil, nil, err
	}
	summary.Secrets = distinctIDs

	if first {
		if _, err := w.Write([]byte("],\n")); err != nil {
			return nil, nil, err
		}
	} else {
		if _, err := w.Write([]byte("\n ],\n")); err != nil {
			return nil, nil, err
		}
	}
	if _, err := w.Write([]byte(" \"Summary\": ")); err != nil {
		return nil, nil, err
	}
	sumJSON, err := json.Marshal(summary)
	if err != nil {
		return nil, nil, err
	}
	if _, err := w.Write(sumJSON); err != nil {
		return nil, nil, err
	}
	if _, err := w.Write([]byte("\n}\n")); err != nil {
		return nil, nil, err
	}
	return summary, infos, nil
}

func writeJSONValue(w io.Writer, v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func (a *Analyzer) scanTip(ctx context.Context) (map[string]struct{}, error) {
	ids := make(map[string]struct{})
	paths, err := a.repo.ListFilesAtCommit(ctx, a.tip)
	if err != nil {
		return nil, fmt.Errorf("list files at tip: %w", err)
	}
	for _, path := range paths {
		data, ok := a.repo.FileAtCommit(ctx, a.tip, path, a.opts.MaxBlobBytes)
		if !ok {
			continue
		}
		found, err := a.tipscan(ctx, path, data)
		if err != nil {
			return nil, fmt.Errorf("scan %s at tip: %w", path, err)
		}
		for _, id := range found {
			ids[id] = struct{}{}
		}
	}
	return ids, nil
}

func (a *Analyzer) buildEntry(ctx context.Context, group []Occurrence, inUseKnown, complete, repoAvailable bool) Entry {
	entry := Entry{
		SecretID:  group[0].SecretID,
		RuleID:    group[0].RuleID,
		Locations: make([]Location, 0, len(group)),
	}

	// Groups arrive sorted by (date, commit, file, line); the first and last
	// records are the first and last observations.
	first := group[0]
	last := group[len(group)-1]

	entry.Info.FirstSeen = &Seen{Commit: first.Commit, Date: first.Date}
	entry.Info.LastSeen = &Seen{Commit: last.Commit, Date: last.Date}
	entry.Info.HistoryComplete = complete

	commits := make(map[string]struct{})
	files := make(map[string]struct{})
	for i := range group {
		o := &group[i]
		if o.Commit != "" {
			commits[o.Commit] = struct{}{}
		}
		files[o.File] = struct{}{}
		entry.Locations = append(entry.Locations, Location{
			Commit:      o.Commit,
			Date:        o.Date,
			File:        o.File,
			StartLine:   o.StartLine,
			EndLine:     o.EndLine,
			StartColumn: o.StartColumn,
			EndColumn:   o.EndColumn,
		})
	}
	entry.Info.Commits = len(commits)
	entry.Info.Files = len(files)

	_, atTip := a.tipIDs[entry.SecretID]
	switch {
	case !repoAvailable:
		entry.Info.Status = StatusNoHistory
	case !inUseKnown || a.tipErr != nil:
		entry.Info.Status = StatusUnknown
	case atTip:
		inUse := true
		entry.Info.Status = StatusInUse
		entry.Info.InUse = &inUse
	case !complete:
		// Absence under incomplete history is not evidence of removal.
		entry.Info.Status = StatusUnknown
	default:
		inUse := false
		entry.Info.Status = StatusNotInUse
		entry.Info.InUse = &inUse
	}

	if repoAvailable {
		refs, merged, historical := a.refMembership(ctx, commits)
		entry.Refs, entry.MergedRefs, entry.HistoricalRefs = refs, merged, historical
		for _, r := range refs {
			if r.Type == "tag" {
				entry.Info.TagCount++
			} else {
				entry.Info.BranchCount++
			}
		}
		entry.Info.MergedBranches = len(merged)
		entry.Info.HistoricalBranches = len(historical)
	}
	return entry
}

// refMembership determines which branches and tags contain at least one of
// the occurrence commits, and whether each ref has been merged into the
// default branch.
func (a *Analyzer) refMembership(ctx context.Context, occCommits map[string]struct{}) ([]Ref, []string, []string) {
	if a.repo == nil || len(occCommits) == 0 {
		return nil, nil, nil
	}
	if len(occCommits) > maxOccurrenceCommits {
		a.repo.note(fmt.Sprintf(
			"ref analysis limited: %d distinct commits exceeds the %d commit budget",
			len(occCommits), maxOccurrenceCommits,
		))
		a.repo.mu.Lock()
		a.repo.diag.RefAnalysisLimited = true
		a.repo.mu.Unlock()
		return nil, nil, nil
	}

	refs, err := a.repo.Refs(ctx)
	if err != nil {
		a.repo.note("ref listing failed; branch/tag membership is unavailable: " + err.Error())
		a.repo.mu.Lock()
		a.repo.diag.RefAnalysisLimited = true
		a.repo.mu.Unlock()
		return nil, nil, nil
	}

	defaultTip := a.tip
	if defaultTip == "" && a.opts.DefaultBranch != "" {
		if sha, err := a.repo.ResolveCommit(ctx, "refs/heads/"+a.opts.DefaultBranch); err == nil {
			defaultTip = sha
		}
	}

	commits := make([]string, 0, len(occCommits))
	for c := range occCommits {
		commits = append(commits, c)
	}
	sort.Strings(commits)

	// For large histories, streaming one rev-list per ref is cheaper than an
	// ancestry query per (commit, ref) pair.
	useStreaming := len(commits)*len(refs) > maxRefMergeBasePairs

	var (
		out        []Ref
		merged     []string
		historical []string
	)

	for _, ref := range refs {
		if ref.SHA == "" {
			continue
		}
		exists, err := a.repo.CommitExists(ctx, ref.SHA)
		if err != nil || !exists {
			// A ref pointing at an unreadable object is recorded and skipped;
			// it never fails the scan, and it bounds the conclusion because
			// history reachable only from that ref was not analyzed.
			a.repo.addSkippedRef(ref.Name)
			continue
		}

		isMerged := false
		if defaultTip != "" {
			ok, err := a.repo.IsAncestor(ctx, ref.SHA, defaultTip)
			if err != nil {
				a.repo.addSkippedRef(ref.Name)
				continue
			}
			isMerged = ok
		}

		contains, err := a.refContains(ctx, ref, commits, useStreaming)
		if err != nil {
			a.repo.addSkippedRef(ref.Name)
			continue
		}
		if !contains {
			continue
		}
		out = append(out, Ref{Name: ref.Name, Type: ref.Type, Merged: isMerged, Tip: ref.SHA})
		if isMerged {
			merged = append(merged, ref.Name)
		} else {
			historical = append(historical, ref.Name)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Name < out[j].Name
	})
	sort.Strings(merged)
	sort.Strings(historical)
	return out, merged, historical
}

func (a *Analyzer) refContains(ctx context.Context, ref gitRef, commits []string, streaming bool) (bool, error) {
	if !streaming {
		for _, c := range commits {
			ok, err := a.repo.IsAncestor(ctx, c, ref.SHA)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	}

	want := make(map[string]struct{}, len(commits))
	for _, c := range commits {
		want[c] = struct{}{}
	}
	var found bool
	err := a.repo.CommitsInRef(ctx, ref.SHA, func(sha string) error {
		if _, ok := want[sha]; ok {
			found = true
			return errStopIteration
		}
		return nil
	})
	if err != nil && err != errStopIteration {
		return false, err
	}
	return found, nil
}

var errStopIteration = fmt.Errorf("stop iteration")

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
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
	if len(out) == 0 {
		return nil
	}
	return out
}

// NormalizeRefName trims a ref to its short name for display.
func NormalizeRefName(ref string) string {
	ref = strings.TrimPrefix(ref, "refs/heads/")
	ref = strings.TrimPrefix(ref, "refs/tags/")
	ref = strings.TrimPrefix(ref, "refs/remotes/origin/")
	return ref
}

// entrySummaries persists one Info per lifecycle entry in a private sidecar
// file so that the analyzer can build the per-finding lookup after the report
// body has been streamed, without holding every entry in memory at once.
type entrySummaries struct {
	path string
	f    *os.File
	w    *bufio.Writer

	closed bool
}

func (e *entrySummaries) write(entry *Entry) error {
	if e.f == nil {
		f, err := os.OpenFile(e.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("create summary sidecar: %w", err)
		}
		e.f = f
		e.w = bufio.NewWriterSize(f, 1<<20)
	}

	// The sidecar stores JSON lines of {SecretID, RuleID, Info}; it is small,
	// ordered and never contains a plaintext secret.
	record := struct {
		SecretID string `json:"s"`
		RuleID   string `json:"r"`
		Info     Info   `json:"i"`
	}{entry.SecretID, entry.RuleID, entry.Info}
	b, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if _, err := e.w.Write(b); err != nil {
		return err
	}
	return e.w.WriteByte('\n')
}

func (e *entrySummaries) close() error {
	if e.closed {
		return nil
	}
	e.closed = true
	if e.w != nil {
		if err := e.w.Flush(); err != nil {
			return err
		}
	}
	if e.f != nil {
		return e.f.Close()
	}
	return nil
}

// load reads the sidecar and returns the distinct-secret count plus the
// per-key lookup. It reuses the parsed record struct's memory per line.
func (e *entrySummaries) load() (int, map[Key]Info, error) {
	infos := make(map[Key]Info)
	distinct := make(map[string]struct{})
	if e.f == nil {
		return 0, infos, nil
	}

	f, err := os.Open(e.path)
	if err != nil {
		return 0, nil, fmt.Errorf("open summary sidecar: %w", err)
	}
	defer f.Close()

	r := bufio.NewReaderSize(f, 1<<20)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			var record struct {
				SecretID string `json:"s"`
				RuleID   string `json:"r"`
				Info     Info   `json:"i"`
			}
			if uerr := json.Unmarshal(line, &record); uerr != nil {
				return 0, nil, fmt.Errorf("corrupt summary sidecar: %w", uerr)
			}
			key := Key{SecretID: record.SecretID, RuleID: record.RuleID}
			infos[key] = record.Info
			distinct[record.SecretID] = struct{}{}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, nil, err
		}
	}
	return len(distinct), infos, nil
}
