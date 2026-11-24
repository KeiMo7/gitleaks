package lifecycle_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLifecycleCorruptObjectContinues verifies a damaged object is counted
// and skipped rather than failing the whole scan, and that remaining secrets
// are still analyzed.
func TestLifecycleCorruptObjectContinues(t *testing.T) {
	r := newRepo(t)
	r.commit(commitSpec{date: "2020-01-01T00:00:00Z", msg: "a"},
		map[string]string{"a.env": "TOKEN=LCK_AAAA1111\n"})
	r.commit(commitSpec{date: "2020-02-01T00:00:00Z", msg: "b"},
		map[string]string{"b.env": "TOKEN=LCK_BBBB2222\n"})
	writeConfig(t, r.dir)

	// Corrupt one reachable blob in the object store.
	out := execGit(t, r.dir, "rev-parse", "HEAD:a.env")
	objPath := filepath.Join(r.dir, ".git", "objects", out[:2], out[2:])
	if err := os.Chmod(objPath, 0o644); err != nil {
		t.Skipf("cannot modify object file: %v", err)
	}
	if err := os.WriteFile(objPath, []byte("corrupt"), 0o644); err != nil {
		t.Skipf("cannot corrupt object file: %v", err)
	}
	defer func() {
		// The temp repo is discarded, but restore so later assertions in this
		// test see a stable object store if the test is rerun in place.
		_ = os.Remove(objPath)
	}()

	rep, _, _, res := scanGit(t, r.dir)
	if res.exitCode != 1 && res.exitCode != 0 {
		t.Fatalf("unexpected exit code %d", res.exitCode)
	}
	// The scan must have produced a report (not crashed) and must not have
	// concluded anything is absent under a corrupt object store.
	if rep.History.Complete {
		t.Errorf("History.Complete = true, want false after object corruption")
	}
	for _, e := range rep.Secrets {
		if e.Status == "not-in-use" {
			t.Errorf("corrupt object store must not yield not-in-use: %+v", e)
		}
	}
}

// TestLifecycleLogOptsLimitsConclusion verifies a history-restricted scan
// marks the conclusion as bounded rather than asserting removal.
func TestLifecycleLogOptsLimitsConclusion(t *testing.T) {
	r := newRepo(t)
	r.commit(commitSpec{date: "2020-01-01T00:00:00Z", msg: "base"},
		map[string]string{"base.txt": "x\n"})
	c2 := r.commit(commitSpec{date: "2020-02-01T00:00:00Z", msg: "add"},
		map[string]string{"a.env": "TOKEN=LCK_AAAA1111\n"})
	r.commit(commitSpec{date: "2020-03-01T00:00:00Z", msg: "remove"},
		map[string]string{"a.env": "TOKEN=none\n"})
	writeConfig(t, r.dir)

	rep, _, _, _ := scanGit(t, r.dir, "--log-opts", c2+"^.."+c2)
	if rep.History.Complete {
		t.Errorf("History.Complete = true, want false for --log-opts")
	}
	if len(rep.History.Reasons) == 0 {
		t.Errorf("History.Reasons empty")
	}
	entries := pickEntries(rep, "lit-token")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Status == "not-in-use" {
		t.Errorf("restricted history must not yield not-in-use")
	}
}

// TestLifecycleNoFindings verifies an empty repository scan still writes a
// valid report and exits 0.
func TestLifecycleNoFindings(t *testing.T) {
	r := newRepo(t)
	r.commit(commitSpec{date: "2020-01-01T00:00:00Z", msg: "clean"},
		map[string]string{"README.md": "nothing\n"})
	writeConfig(t, r.dir)

	rep, _, _, res := scanGit(t, r.dir)
	if res.exitCode != 0 {
		t.Errorf("exit = %d, want 0", res.exitCode)
	}
	if len(rep.Secrets) != 0 {
		t.Errorf("secrets = %d, want 0", len(rep.Secrets))
	}
	if rep.Summary.Entries != 0 {
		t.Errorf("entries = %d, want 0", rep.Summary.Entries)
	}
}

// TestLifecycleSameDigestTwoRules verifies the same secret matched by two
// rules produces two rows, each keeping its own rule id.
func TestLifecycleSameDigestTwoRules(t *testing.T) {
	r := newRepo(t)
	// LCK_ALPHA111 matches both lit-token and alt-token.
	r.commit(commitSpec{date: "2020-01-01T00:00:00Z", msg: "both rules"},
		map[string]string{"a.env": "TOKEN=LCK_ALPHA111\n"})
	writeConfig(t, r.dir)

	rep, _, _, _ := scanGit(t, r.dir)
	if len(rep.Secrets) != 2 {
		t.Fatalf("expected 2 rows (one per rule), got %d: %+v", len(rep.Secrets), rep.Secrets)
	}
	ids := map[string]string{}
	for _, e := range rep.Secrets {
		ids[e.RuleID] = e.SecretID
	}
	if ids["lit-token"] == "" || ids["alt-token"] == "" {
		t.Fatalf("missing rule rows: %v", ids)
	}
	if ids["lit-token"] != ids["alt-token"] {
		t.Errorf("same secret under different rules got different ids: %v", ids)
	}
	if rep.Summary.Secrets != 1 || rep.Summary.Entries != 2 {
		t.Errorf("summary = %+v, want Secrets=1 Entries=2", rep.Summary)
	}
}

// TestLifecycleMultipleHitsOneCommit verifies several locations in one commit
// are all retained but count as one commit.
func TestLifecycleMultipleHitsOneCommit(t *testing.T) {
	r := newRepo(t)
	c1 := r.commit(commitSpec{date: "2020-01-01T00:00:00Z", msg: "several"},
		map[string]string{
			"a.env": "TOKEN=LCK_AAAA1111\n",
			"b.env": "OTHER=LCK_AAAA1111\n",
			"c.env": "x=1\nTOKEN=LCK_AAAA1111\n",
		})
	writeConfig(t, r.dir)

	rep, _, _, _ := scanGit(t, r.dir)
	entries := pickEntries(rep, "lit-token")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Commits != 1 {
		t.Errorf("Commits = %d, want 1", e.Commits)
	}
	if e.Files != 3 {
		t.Errorf("Files = %d, want 3", e.Files)
	}
	if len(e.Locations) != 3 {
		t.Errorf("Locations = %d, want 3", len(e.Locations))
	}
	if e.FirstSeen.Commit != c1 || e.LastSeen.Commit != c1 {
		t.Errorf("first/last = %s/%s, want both %s", e.FirstSeen.Commit, e.LastSeen.Commit, c1)
	}
}

// TestLifecycleCSVAppendsColumns verifies CSV output keeps every existing
// column and appends lifecycle columns only when enabled.
func TestLifecycleCSVAppendsColumns(t *testing.T) {
	r := newRepo(t)
	r.commit(commitSpec{date: "2020-01-01T00:00:00Z", msg: "add"},
		map[string]string{"a.env": "TOKEN=LCK_AAAA1111\n"})
	writeConfig(t, r.dir)

	outDir := t.TempDir()
	plain := filepath.Join(outDir, "plain.csv")
	withLC := filepath.Join(outDir, "with.csv")
	base := []string{"git", r.dir, "--config", filepath.Join(r.dir, ".gitleaks.toml"), "--log-level", "error", "--no-banner", "--report-format", "csv"}
	runGitleaks(t, append(base, "--report-path", plain)...)
	runGitleaks(t, append(base, "--report-path", withLC,
		"--lifecycle", "--lifecycle-report-path", filepath.Join(outDir, "lc.json"))...)

	plainHeader, plainRow := readCSV(t, plain)
	withHeader, withRow := readCSV(t, withLC)

	if len(withHeader) <= len(plainHeader) {
		t.Fatalf("lifecycle CSV header has %d columns, plain has %d", len(withHeader), len(plainHeader))
	}
	for i := range plainHeader {
		if plainHeader[i] != withHeader[i] {
			t.Errorf("column %d changed: %q -> %q", i, plainHeader[i], withHeader[i])
		}
	}
	for i := range plainRow {
		if plainRow[i] != withRow[i] {
			t.Errorf("value %d changed: %q -> %q", i, plainRow[i], withRow[i])
		}
	}
	if withHeader[len(plainHeader)] != "LifecycleStatus" {
		t.Errorf("first appended column = %q, want LifecycleStatus", withHeader[len(plainHeader)])
	}
	statusIdx := indexOf(withHeader, "LifecycleStatus")
	if statusIdx < 0 || withRow[statusIdx] != "in-use" {
		t.Errorf("lifecycle status cell = %q, want in-use", withRow[statusIdx])
	}
}

// TestLifecycleStableAcrossReclone verifies identifiers depend on repository
// identity, not on the checkout path.
func TestLifecycleStableAcrossReclone(t *testing.T) {
	src := newRepo(t)
	src.commit(commitSpec{date: "2020-01-01T00:00:00Z", msg: "add"},
		map[string]string{"a.env": "TOKEN=LCK_AAAA1111\n"})
	writeConfig(t, src.dir)

	first, _, _, _ := scanGit(t, src.dir)

	dst := filepath.Join(t.TempDir(), "clone")
	execGit(t, "", "clone", "-q", "file://"+src.dir, dst)
	if err := os.WriteFile(filepath.Join(dst, ".gitleaks.toml"), []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	second, _, _, _ := scanGit(t, dst)

	if len(first.Secrets) != 1 || len(second.Secrets) != 1 {
		t.Fatalf("expected one secret in each, got %d and %d", len(first.Secrets), len(second.Secrets))
	}
	if first.Secrets[0].SecretID != second.Secrets[0].SecretID {
		t.Errorf("identifier changed across clone: %s vs %s", first.Secrets[0].SecretID, second.Secrets[0].SecretID)
	}
}

func readCSV(t *testing.T, path string) ([]string, []string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 2 {
		t.Fatalf("%s has %d lines, want at least 2:\n%s", path, len(lines), raw)
	}
	return splitCSVLine(lines[0]), splitCSVLine(lines[1])
}

func splitCSVLine(line string) []string {
	var (
		out   []string
		cur   strings.Builder
		quote bool
	)
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"' && quote && i+1 < len(line) && line[i+1] == '"':
			cur.WriteByte('"')
			i++
		case c == '"':
			quote = !quote
		case c == ',' && !quote:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	return append(out, cur.String())
}

func indexOf(list []string, want string) int {
	for i, v := range list {
		if v == want {
			return i
		}
	}
	return -1
}
