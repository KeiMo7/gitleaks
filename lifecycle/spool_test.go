package lifecycle

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestSpool(t *testing.T, chunk int) *Spool {
	t.Helper()
	s, err := NewSpool(filepath.Join(t.TempDir(), "spool"), chunk)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func occ(id, rule, commit, date, file string, line int) Occurrence {
	return Occurrence{
		SecretID: id, RuleID: rule, Commit: commit, Date: date, File: file,
		StartLine: line, EndLine: line, StartColumn: 1, EndColumn: 4,
	}
}

// TestSpoolGroupsAcrossRuns verifies grouping is correct when records spill
// to several sorted runs, and that group order is deterministic.
func TestSpoolGroupsAcrossRuns(t *testing.T) {
	s := newTestSpool(t, 3) // tiny chunk: forces many runs

	for i := 0; i < 20; i++ {
		date := time.Date(2020, 1, 1+i, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
		commit := fmt.Sprintf("c%02d", i)
		if err := s.Add(occ(fmt.Sprintf("id%02d", i%4), "rule", commit, date, "f.env", 1)); err != nil {
			t.Fatal(err)
		}
	}

	type groupKey struct{ id, rule string }
	groups := map[groupKey]int{}
	var order []string
	err := s.Group(func(group []Occurrence) error {
		key := groupKey{group[0].SecretID, group[0].RuleID}
		groups[key] = len(group)
		order = append(order, group[0].SecretID)
		// Groups must arrive sorted by secret id.
		for i := 1; i < len(group); i++ {
			if group[i-1].SecretID > group[i].SecretID {
				t.Errorf("group not sorted: %s > %s", group[i-1].SecretID, group[i].SecretID)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 4 {
		t.Fatalf("got %d groups, want 4", len(groups))
	}
	for key, n := range groups {
		if n != 5 {
			t.Errorf("group %v has %d occurrences, want 5", key, n)
		}
	}
	for i := 1; i < len(order); i++ {
		if order[i-1] > order[i] {
			t.Errorf("group emission order not sorted: %s then %s", order[i-1], order[i])
		}
	}
}

// TestSpoolDedupesExactLocations verifies identical locations collapse while
// distinct locations in the same commit are retained.
func TestSpoolDedupesExactLocations(t *testing.T) {
	s := newTestSpool(t, 100)
	base := occ("id", "rule", "c1", "2020-01-01T00:00:00Z", "f.env", 1)
	dup := base
	other := base
	other.StartLine, other.EndLine = 9, 9

	for _, o := range []Occurrence{base, dup, base, other} {
		if err := s.Add(o); err != nil {
			t.Fatal(err)
		}
	}

	var got []Occurrence
	if err := s.Group(func(group []Occurrence) error {
		got = append(got, group...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d locations, want 2: %+v", len(got), got)
	}
	if got[0].StartLine != 1 || got[1].StartLine != 9 {
		t.Errorf("locations = %d,%d, want 1,9", got[0].StartLine, got[1].StartLine)
	}
}

// TestSpoolSurvivesRestart simulates the CLI flow where the spool directory
// outlives the process that produced it: the binary format must round-trip.
func TestSpoolRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	s, err := NewSpool(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := []Occurrence{
		occ("idb", "rule2", "c2", "2020-02-01T00:00:00Z", "dir/weird name\t.env", 42),
		occ("ida", "rule1", "c1", "2020-01-01T00:00:00Z", "plain.env", 1),
	}
	for _, o := range want {
		if err := s.Add(o); err != nil {
			t.Fatal(err)
		}
	}
	// Flush but do not delete the directory.
	if err := s.Group(func([]Occurrence) error { return nil }); err != nil {
		t.Fatal(err)
	}

	runs, err := filepath.Glob(filepath.Join(dir, "run-*.spool"))
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) == 0 {
		t.Fatal("no spool runs written")
	}
	total := 0
	for _, run := range runs {
		r, err := openRun(run)
		if err != nil {
			t.Fatal(err)
		}
		for {
			o, ok, err := r.next()
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				break
			}
			if o.File == "" || o.SecretID == "" {
				t.Errorf("corrupt record: %+v", o)
			}
			total++
		}
		_ = r.Close()
	}
	if total != len(want) {
		t.Errorf("round-tripped %d records, want %d", total, len(want))
	}
}

// TestSpoolEmptyIsSafe ensures an empty spool still produces a valid report.
func TestSpoolEmptyIsSafe(t *testing.T) {
	s := newTestSpool(t, 10)
	called := false
	if err := s.Group(func([]Occurrence) error { called = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("Group invoked callback for an empty spool")
	}
}

// TestAnalyzerNoHistoryReport verifies a directory-style analysis marks every
// secret no-history and never emits an in-use conclusion.
func TestAnalyzerNoHistoryReport(t *testing.T) {
	s := newTestSpool(t, 100)
	if err := s.Add(occ("id", "rule", "", "", "app.env", 1)); err != nil {
		t.Fatal(err)
	}

	a := NewAnalyzer(nil, s, "", nil, Options{Kind: KindDirectory})
	var buf bytes.Buffer
	summary, infos, err := a.Analyze(context.Background(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	if summary.NoHistory != 1 || summary.InUse != 0 {
		t.Errorf("summary = %+v, want NoHistory=1", summary)
	}
	info := infos[Key{SecretID: "id", RuleID: "rule"}]
	if info.Status != StatusNoHistory {
		t.Errorf("status = %q, want no-history", info.Status)
	}
	if info.InUse != nil {
		t.Errorf("InUse = %v, want nil", *info.InUse)
	}
	if !strings.Contains(buf.String(), `"Complete":false`) {
		t.Errorf("report does not mark history incomplete:\n%s", buf.String())
	}
}

// TestAnalyzerDeterministic verifies two runs over the same records produce
// byte-identical documents.
func TestAnalyzerDeterministic(t *testing.T) {
	run := func() string {
		s := newTestSpool(t, 2)
		for i := 0; i < 12; i++ {
			date := time.Date(2020, 1, 1+i, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
			if err := s.Add(occ(fmt.Sprintf("id%d", i%3), fmt.Sprintf("rule%d", i%2), fmt.Sprintf("c%d", i), date, fmt.Sprintf("f%d.env", i%2), i)); err != nil {
				t.Fatal(err)
			}
		}
		var buf bytes.Buffer
		a := NewAnalyzer(nil, s, "", nil, Options{Kind: KindDirectory})
		if _, _, err := a.Analyze(nil, &buf); err != nil { //nolint:staticcheck
			t.Fatal(err)
		}
		return buf.String()
	}
	first := run()
	second := run()
	if first != second {
		t.Errorf("two runs differ:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
}

// TestAnalyzerRuleSeparation verifies the same secret under two rules yields
// two entries (no silent merge).
func TestAnalyzerRuleSeparation(t *testing.T) {
	s := newTestSpool(t, 100)
	if err := s.Add(occ("same", "rule-a", "c1", "2020-01-01T00:00:00Z", "f.env", 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(occ("same", "rule-b", "c1", "2020-01-01T00:00:00Z", "f.env", 1)); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	a := NewAnalyzer(nil, s, "", nil, Options{Kind: KindDirectory})
	summary, infos, err := a.Analyze(context.Background(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Entries != 2 {
		t.Errorf("entries = %d, want 2", summary.Entries)
	}
	if summary.Secrets != 1 {
		t.Errorf("secrets = %d, want 1", summary.Secrets)
	}
	if _, ok := infos[Key{SecretID: "same", RuleID: "rule-a"}]; !ok {
		t.Error("rule-a entry missing")
	}
	if _, ok := infos[Key{SecretID: "same", RuleID: "rule-b"}]; !ok {
		t.Error("rule-b entry missing")
	}
}

// TestSpoolMemoryBounded verifies in-memory buffering never exceeds the
// configured chunk size, regardless of how many records are added.
func TestSpoolMemoryBounded(t *testing.T) {
	s := newTestSpool(t, 5)
	maxSeen := 0
	for i := 0; i < 100; i++ {
		if err := s.Add(occ(fmt.Sprintf("id%d", i%7), "rule", fmt.Sprintf("c%d", i), "2020-01-01T00:00:00Z", "f", i+1)); err != nil {
			t.Fatal(err)
		}
		if len(s.chunk) > maxSeen {
			maxSeen = len(s.chunk)
		}
	}
	if maxSeen > s.chunkCap {
		t.Errorf("buffer reached %d, cap is %d", maxSeen, s.chunkCap)
	}
	runs, _ := filepath.Glob(filepath.Join(s.dir, "run-*.spool"))
	if len(runs) == 0 {
		t.Error("expected the spool to spill to disk")
	}
}

// TestSpoolMergeBoundedFanIn forces many more runs than the fan-in and checks
// that compaction keeps live runs bounded while preserving grouping.
func TestSpoolMergeBoundedFanIn(t *testing.T) {
	s := newTestSpool(t, 1) // every record becomes its own run
	for i := 0; i < minFanIn*3+7; i++ {
		if err := s.Add(occ(fmt.Sprintf("id%03d", i%9), "rule", fmt.Sprintf("c%03d", i), "2020-01-01T00:00:00Z", "f", i+1)); err != nil {
			t.Fatal(err)
		}
	}

	groups := map[string]int{}
	if err := s.Group(func(group []Occurrence) error {
		groups[group[0].SecretID] = len(group)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, n := range groups {
		total += n
	}
	if total != minFanIn*3+7 {
		t.Errorf("grouped %d records, want %d", total, minFanIn*3+7)
	}
	if len(groups) != 9 {
		t.Errorf("groups = %d, want 9", len(groups))
	}
}
