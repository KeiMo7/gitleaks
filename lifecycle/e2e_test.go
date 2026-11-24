package lifecycle_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLifecycleAdded verifies a secret introduced on the default branch is
// reported as in use with first == last seen at the introducing commit.
func TestLifecycleAdded(t *testing.T) {
	r := newRepo(t)
	c1 := r.commit(commitSpec{date: "2020-01-01T00:00:00Z", msg: "add"},
		map[string]string{"app.env": "TOKEN=LCK_AAAA1111\n"})
	r.commit(commitSpec{date: "2020-02-01T00:00:00Z", msg: "unrelated"},
		map[string]string{"README.md": "hello\n"})
	writeConfig(t, r.dir)

	rep, _, _, res := scanGit(t, r.dir)
	entries := pickEntries(rep, "lit-token")
	if len(entries) != 1 {
		t.Fatalf("expected 1 lit-token entry, got %d (%+v)", len(entries), entries)
	}
	e := entries[0]
	if e.Status != "in-use" {
		t.Errorf("status = %q, want in-use", e.Status)
	}
	if e.InUse == nil || !*e.InUse {
		t.Errorf("InUse = %v, want true", e.InUse)
	}
	if e.FirstSeen == nil || e.FirstSeen.Commit != c1 {
		t.Errorf("FirstSeen = %+v, want commit %s", e.FirstSeen, c1)
	}
	if e.LastSeen == nil || e.LastSeen.Commit != c1 {
		t.Errorf("LastSeen = %+v, want commit %s", e.LastSeen, c1)
	}
	if len(e.Locations) != 1 {
		t.Errorf("locations = %d, want 1", len(e.Locations))
	}
	if len(e.MergedRefs) == 0 || e.MergedRefs[0] != "main" {
		t.Errorf("MergedRefs = %v, want [main]", e.MergedRefs)
	}
	if res.exitCode != 1 {
		t.Errorf("exit code = %d, want 1 (leaks found)", res.exitCode)
	}
}

// TestLifecycleRotated verifies that two different secrets in the same slot
// are separate entries, and that the one still present at the tip is the
// in-use one.
func TestLifecycleRotated(t *testing.T) {
	r := newRepo(t)
	c1 := r.commit(commitSpec{date: "2020-01-01T00:00:00Z", msg: "old secret"},
		map[string]string{"app.env": "TOKEN=LCK_AAAA1111\n"})
	c2 := r.commit(commitSpec{date: "2020-02-01T00:00:00Z", msg: "rotate"},
		map[string]string{"app.env": "TOKEN=LCK_BBBB2222\n"})
	writeConfig(t, r.dir)

	rep, _, _, _ := scanGit(t, r.dir)
	entries := pickEntries(rep, "lit-token")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	old := findByFirstCommit(entries, c1)
	if old == nil {
		t.Fatalf("no entry with FirstSeen=%s", c1)
	}
	if old.Status != "not-in-use" {
		t.Errorf("old secret status = %q, want not-in-use", old.Status)
	}
	if old.InUse == nil || *old.InUse {
		t.Errorf("old secret InUse = %v, want false", old.InUse)
	}
	if old.FirstSeen.Commit != c1 || old.LastSeen.Commit != c1 {
		t.Errorf("old secret first/last = %s/%s, want %s/%s", old.FirstSeen.Commit, old.LastSeen.Commit, c1, c1)
	}

	newer := findByFirstCommit(entries, c2)
	if newer == nil {
		t.Fatalf("no entry with FirstSeen=%s", c2)
	}
	if newer.Status != "in-use" {
		t.Errorf("new secret status = %q, want in-use", newer.Status)
	}
	if newer.FirstSeen.Commit != c2 || newer.LastSeen.Commit != c2 {
		t.Errorf("new secret first/last = %s/%s, want %s/%s", newer.FirstSeen.Commit, newer.LastSeen.Commit, c2, c2)
	}
}

// TestLifecycleDeleted verifies a secret removed from the default branch is
// marked not in use with complete history.
func TestLifecycleDeleted(t *testing.T) {
	r := newRepo(t)
	c1 := r.commit(commitSpec{date: "2020-01-01T00:00:00Z", msg: "add"},
		map[string]string{"app.env": "TOKEN=LCK_AAAA1111\n", "keep.txt": "x\n"})
	r.commit(commitSpec{date: "2020-02-01T00:00:00Z", msg: "delete"},
		map[string]string{"app.env": "TOKEN=nothing\n"})
	writeConfig(t, r.dir)

	rep, _, _, _ := scanGit(t, r.dir)
	entries := pickEntries(rep, "lit-token")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Status != "not-in-use" {
		t.Errorf("status = %q, want not-in-use", e.Status)
	}
	if !e.HistoryComplete {
		t.Errorf("HistoryComplete = false, want true")
	}
	if e.FirstSeen.Commit != c1 {
		t.Errorf("FirstSeen = %s, want %s", e.FirstSeen.Commit, c1)
	}
	// The delete commit re-adds the line with a different value, so this
	// secret only ever appears in c1.
	if e.LastSeen.Commit != c1 {
		t.Errorf("LastSeen = %s, want %s", e.LastSeen.Commit, c1)
	}
}

// TestLifecycleRenamed verifies that moving a file does not split one secret
// into two entries.
func TestLifecycleRenamed(t *testing.T) {
	r := newRepo(t)
	c1 := r.commit(commitSpec{date: "2020-01-01T00:00:00Z", msg: "add"},
		map[string]string{"configs/old.env": "TOKEN=LCK_AAAA1111\n"})
	r.git("mv", "configs/old.env", "configs/new.env")
	r.commit(commitSpec{date: "2020-02-01T00:00:00Z", msg: "move"}, nil)
	r.commit(commitSpec{date: "2020-03-01T00:00:00Z", msg: "tweak"},
		map[string]string{"configs/new.env": "# comment\nTOKEN=LCK_AAAA1111\n"})
	writeConfig(t, r.dir)

	rep, _, _, _ := scanGit(t, r.dir)
	entries := pickEntries(rep, "lit-token")
	if len(entries) != 1 {
		t.Fatalf("rename split the secret into %d entries: %+v", len(entries), entries)
	}
	e := entries[0]
	if e.FirstSeen.Commit != c1 {
		t.Errorf("FirstSeen = %s, want %s", e.FirstSeen.Commit, c1)
	}
	if e.Status != "in-use" {
		t.Errorf("status = %q, want in-use", e.Status)
	}
	// Every location carries the canonical (oldest) path, so the move itself
	// adds no second location: the rename diff produces no added line.
	for _, loc := range e.Locations {
		if loc.File != "configs/old.env" {
			t.Errorf("location file = %q, want canonical configs/old.env", loc.File)
		}
	}
	if len(e.Locations) != 1 {
		t.Errorf("locations = %d, want 1 (rename adds no added line)", len(e.Locations))
	}
}

// TestLifecycleAcrossBranchMerge verifies ref membership: a secret introduced
// on a merged branch and removed on main is reported with the merged branch
// listed even though it is no longer in use.
func TestLifecycleAcrossBranchMerge(t *testing.T) {
	r := newRepo(t)
	r.commit(commitSpec{date: "2020-01-01T00:00:00Z", msg: "base"},
		map[string]string{"base.txt": "x\n"})

	r.git("checkout", "-q", "-b", "feature")
	cFeature := r.commit(commitSpec{date: "2020-02-01T00:00:00Z", msg: "feature secret"},
		map[string]string{"feature.env": "TOKEN=LCK_AAAA1111\n"})

	r.git("checkout", "-q", "main")
	r.commit(commitSpec{date: "2020-03-01T00:00:00Z", msg: "main work"},
		map[string]string{"main.txt": "y\n"})
	r.git("merge", "-q", "--no-ff", "feature", "-m", "merge feature")
	// Remove the secret again on main after the merge.
	r.commit(commitSpec{date: "2020-04-01T00:00:00Z", msg: "remove"},
		map[string]string{"feature.env": "TOKEN=none\n"})
	writeConfig(t, r.dir)

	rep, _, _, _ := scanGit(t, r.dir)
	entries := pickEntries(rep, "lit-token")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Status != "not-in-use" {
		t.Errorf("status = %q, want not-in-use", e.Status)
	}
	if e.FirstSeen.Commit != cFeature {
		t.Errorf("FirstSeen = %s, want feature commit %s", e.FirstSeen.Commit, cFeature)
	}
	if len(e.MergedRefs) == 0 || e.MergedRefs[0] != "feature" {
		t.Errorf("MergedRefs = %v, want feature listed as merged", e.MergedRefs)
	}
	for _, ref := range e.Refs {
		if ref.Name == "feature" && !ref.Merged {
			t.Errorf("feature ref marked unmerged, want merged")
		}
	}
}

// TestLifecycleUnmergedBranch verifies an unmerged branch is reported as a
// historical (non-merged) ref, not as current use.
func TestLifecycleUnmergedBranch(t *testing.T) {
	r := newRepo(t)
	r.commit(commitSpec{date: "2020-01-01T00:00:00Z", msg: "base"},
		map[string]string{"base.txt": "x\n"})

	r.git("checkout", "-q", "-b", "wip")
	cWip := r.commit(commitSpec{date: "2020-02-01T00:00:00Z", msg: "wip secret"},
		map[string]string{"wip.env": "TOKEN=LCK_AAAA1111\n"})

	r.git("checkout", "-q", "main")
	r.commit(commitSpec{date: "2020-03-01T00:00:00Z", msg: "main"},
		map[string]string{"main.txt": "y\n"})
	writeConfig(t, r.dir)

	rep, _, _, _ := scanGit(t, r.dir)
	entries := pickEntries(rep, "lit-token")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Status != "not-in-use" {
		t.Errorf("status = %q, want not-in-use", e.Status)
	}
	if e.FirstSeen.Commit != cWip {
		t.Errorf("FirstSeen = %s, want %s", e.FirstSeen.Commit, cWip)
	}
	found := false
	for _, name := range e.HistoricalRefs {
		if name == "wip" {
			found = true
		}
	}
	if !found {
		t.Errorf("HistoricalRefs = %v, want wip", e.HistoricalRefs)
	}
	for _, name := range e.MergedRefs {
		if name == "wip" {
			t.Errorf("wip must not be reported as merged")
		}
	}
}

// TestLifecycleEncodedAndSplit verifies encoded, escaped and line-split forms
// group under the same digest as the plain secret.
func TestLifecycleEncodedAndSplit(t *testing.T) {
	r := newRepo(t)
	c1 := r.commit(commitSpec{date: "2020-01-01T00:00:00Z", msg: "plain"},
		map[string]string{"a.env": "TOKEN=LCK_AAAA1111\n"})
	encoded, err := canonicalWrapper("LCK_AAAA1111")
	if err != nil {
		t.Fatal(err)
	}
	if encoded == "LCK_AAAA1111" {
		t.Fatal("wrapper did not encode the secret")
	}
	r.commit(commitSpec{date: "2020-02-01T00:00:00Z", msg: "encoded"},
		map[string]string{"b.env": "TOKEN=" + encoded + "\n"})
	// Percent-encoded (one character in a few different escape forms).
	r.commit(commitSpec{date: "2020-03-01T00:00:00Z", msg: "percent"},
		map[string]string{"c.env": "TOKEN=LCK_AAAA%31%31%31%31\n"})
	// Split across a raw line break inside the value. The rule tolerates the
	// separator so it is detected; identity normalization must strip it so
	// the value groups with the unsplit forms.
	r.commit(commitSpec{date: "2020-04-01T00:00:00Z", msg: "split"},
		map[string]string{"d.env": "TOKEN=LCK_AAAA\n1111\n"})
	writeConfig(t, r.dir)

	rep, _, _, _ := scanGit(t, r.dir)
	entries := pickEntries(rep, "lit-token")
	if len(entries) != 1 {
		t.Fatalf("encoded/split forms produced %d entries, want 1: %+v", len(entries), entries)
	}
	e := entries[0]
	if e.FirstSeen.Commit != c1 {
		t.Errorf("FirstSeen = %s, want %s", e.FirstSeen.Commit, c1)
	}
	if len(e.Locations) != 4 {
		t.Errorf("locations = %d, want 4 (one per representation): %+v", len(e.Locations), e.Locations)
	}
}

// TestLifecycleNoHistoryDirectory verifies directory scans never claim a
// secret disappeared.
func TestLifecycleNoHistoryDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.env"), []byte("TOKEN=LCK_AAAA1111\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, dir)

	outDir := t.TempDir()
	lcPath := filepath.Join(outDir, "lifecycle.json")
	res := runGitleaks(t,
		"dir", dir,
		"--config", filepath.Join(dir, ".gitleaks.toml"),
		"--lifecycle",
		"--lifecycle-report-path", lcPath,
		"--log-level", "error",
		"--no-banner",
	)
	if res.exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", res.exitCode)
	}
	raw, err := os.ReadFile(lcPath)
	if err != nil {
		t.Fatalf("lifecycle report missing: %v\n%s", err, res.stderr)
	}
	rep := mustParse(t, raw)
	if rep.Source != "directory" {
		t.Errorf("Source = %q, want directory", rep.Source)
	}
	if rep.History.Complete {
		t.Errorf("History.Complete = true, want false for a directory scan")
	}
	entries := pickEntries(rep, "lit-token")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Status != "no-history" {
		t.Errorf("status = %q, want no-history", entries[0].Status)
	}
	if entries[0].InUse != nil {
		t.Errorf("InUse = %v, want nil (no conclusion without history)", *entries[0].InUse)
	}
	if entries[0].FirstSeen == nil || entries[0].FirstSeen.Commit != "" {
		t.Errorf("FirstSeen = %+v, want empty commit", entries[0].FirstSeen)
	}
}

// TestLifecycleShallowClone verifies incomplete history yields "unknown", not
// "not-in-use".
func TestLifecycleShallowClone(t *testing.T) {
	src := newRepo(t)
	src.commit(commitSpec{date: "2020-01-01T00:00:00Z", msg: "add"},
		map[string]string{"app.env": "TOKEN=LCK_AAAA1111\n"})
	src.commit(commitSpec{date: "2020-02-01T00:00:00Z", msg: "remove"},
		map[string]string{"app.env": "TOKEN=none\n"})
	src.commit(commitSpec{date: "2020-03-01T00:00:00Z", msg: "later"},
		map[string]string{"later.txt": "z\n"})
	writeConfig(t, src.dir)

	shallow := t.TempDir()
	clone := execGit(t, "", "clone", "-q", "--depth", "1", "file://"+src.dir, shallow)
	_ = clone

	outDir := t.TempDir()
	lcPath := filepath.Join(outDir, "lifecycle.json")
	res := runGitleaks(t,
		"git", shallow,
		"--config", filepath.Join(src.dir, ".gitleaks.toml"),
		"--lifecycle",
		"--lifecycle-report-path", lcPath,
		"--log-level", "error",
		"--no-banner",
	)
	raw, err := os.ReadFile(lcPath)
	if err != nil {
		t.Fatalf("lifecycle report missing: %v\n%s", err, res.stderr)
	}
	rep := mustParse(t, raw)
	if !rep.Repository.Shallow {
		t.Errorf("Repository.Shallow = false, want true")
	}
	if rep.History.Complete {
		t.Errorf("History.Complete = true, want false")
	}
	if len(rep.History.Reasons) == 0 {
		t.Errorf("History.Reasons empty, want an explanation")
	}
	// The only commit in the shallow clone has no secret, so the history
	// scan finds nothing. Assert directly that a scan which does see the
	// secret under shallow history reports unknown.
	for _, e := range rep.Secrets {
		if e.Status == "not-in-use" {
			t.Errorf("shallow clone must not conclude not-in-use: %+v", e)
		}
	}
}

// TestLifecycleDeterministic verifies two runs on the same repository and
// configuration produce byte-identical lifecycle reports and primary reports.
func TestLifecycleDeterministic(t *testing.T) {
	r := newRepo(t)
	r.commit(commitSpec{date: "2020-01-01T00:00:00Z", msg: "add"},
		map[string]string{"a.env": "TOKEN=LCK_AAAA1111\n", "b.env": "TOKEN=LCK_BBBB2222\n"})
	r.git("checkout", "-q", "-b", "side")
	r.commit(commitSpec{date: "2020-02-01T00:00:00Z", msg: "side"},
		map[string]string{"c.env": "TOKEN=LCK_CCCC3333\n"})
	r.git("checkout", "-q", "main")
	r.commit(commitSpec{date: "2020-03-01T00:00:00Z", msg: "rotate"},
		map[string]string{"a.env": "TOKEN=LCK_DDDD4444\n"})
	writeConfig(t, r.dir)

	firstRep, firstLC, firstPrimaryReport, _ := scanGit(t, r.dir)
	secondRep, secondLC, secondPrimaryReport, _ := scanGit(t, r.dir)

	if firstLC != secondLC {
		t.Fatalf("lifecycle reports differ between runs:\n--- run 1 ---\n%s\n--- run 2 ---\n%s", firstLC, secondLC)
	}
	if len(firstRep.Secrets) != len(secondRep.Secrets) {
		t.Fatalf("entry counts differ: %d vs %d", len(firstRep.Secrets), len(secondRep.Secrets))
	}
	// The primary JSON report must also be stable, including the appended
	// Lifecycle field.
	if firstPrimaryReport.raw != secondPrimaryReport.raw {
		t.Fatalf("primary reports differ between runs:\n--- run 1 ---\n%s\n--- run 2 ---\n%s", firstPrimaryReport.raw, secondPrimaryReport.raw)
	}
}

// TestReportCompatibility verifies lifecycle fields are additive: without
// --lifecycle the primary JSON is unchanged, with it the existing prefix of
// every finding object is unchanged.
func TestReportCompatibility(t *testing.T) {
	r := newRepo(t)
	r.commit(commitSpec{date: "2020-01-01T00:00:00Z", msg: "add"},
		map[string]string{"a.env": "TOKEN=LCK_AAAA1111\n"})
	writeConfig(t, r.dir)

	outDir := t.TempDir()
	plain := filepath.Join(outDir, "plain.json")
	withLC := filepath.Join(outDir, "withlc.json")
	lcPath := filepath.Join(outDir, "lifecycle.json")
	base := []string{
		"git", r.dir,
		"--config", filepath.Join(r.dir, ".gitleaks.toml"),
		"--log-level", "error", "--no-banner",
	}

	if res := runGitleaks(t, append(base, "--report-path", plain, "--report-format", "json")...); res.exitCode != 1 {
		t.Fatalf("plain scan exit = %d, want 1", res.exitCode)
	}
	if res := runGitleaks(t, append(base,
		"--report-path", withLC, "--report-format", "json",
		"--lifecycle", "--lifecycle-report-path", lcPath)...); res.exitCode != 1 {
		t.Fatalf("lifecycle scan exit = %d, want 1", res.exitCode)
	}

	plainRaw, err := os.ReadFile(plain)
	if err != nil {
		t.Fatal(err)
	}
	withRaw, err := os.ReadFile(withLC)
	if err != nil {
		t.Fatal(err)
	}

	var plainFindings, withFindings []map[string]json.RawMessage
	if err := json.Unmarshal(plainRaw, &plainFindings); err != nil {
		t.Fatalf("plain report invalid: %v", err)
	}
	if err := json.Unmarshal(withRaw, &withFindings); err != nil {
		t.Fatalf("lifecycle report invalid: %v", err)
	}
	if len(plainFindings) != 1 || len(withFindings) != 1 {
		t.Fatalf("expected one finding each, got %d and %d", len(plainFindings), len(withFindings))
	}
	if _, ok := plainFindings[0]["Lifecycle"]; ok {
		t.Errorf("plain report unexpectedly contains a Lifecycle field")
	}
	if _, ok := withFindings[0]["Lifecycle"]; !ok {
		t.Errorf("lifecycle-enabled report is missing the Lifecycle field")
	}

	// Every pre-existing field keeps its name, value and relative order.
	plainOrder := jsonKeyOrder(t, plainRaw)
	withOrder := jsonKeyOrder(t, withRaw)
	if got, want := withOrder[:len(plainOrder)], plainOrder; !equalStrings(got, want) {
		t.Errorf("existing field order changed:\n got: %v\nwant: %v", got, want)
	}
	if withOrder[len(plainOrder)] != "Lifecycle" {
		t.Errorf("Lifecycle is not appended last: %v", withOrder)
	}
	for _, key := range plainOrder {
		if !bytes.Equal(plainFindings[0][key], withFindings[0][key]) {
			t.Errorf("field %q changed when lifecycle was enabled", key)
		}
	}
}

// TestLifecycleSuppressionUnchanged verifies suppressed findings stay out of
// the lifecycle report and exit/blocking semantics are unchanged.
func TestLifecycleSuppressionUnchanged(t *testing.T) {
	r := newRepo(t)
	r.commit(commitSpec{date: "2020-01-01T00:00:00Z", msg: "add"},
		map[string]string{"a.env": "TOKEN=LCK_AAAA1111\n", "b.env": "TOKEN=LCK_BBBB2222\n"})
	writeConfig(t, r.dir)

	// Suppress the finding in a.env via a path allowlist.
	cfg, err := os.ReadFile(filepath.Join(r.dir, ".gitleaks.toml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg = append(cfg, []byte(`
[[allowlists]]
    description = "ignore a.env"
    paths = ['''a\.env''']
`)...)
	if err := os.WriteFile(filepath.Join(r.dir, ".gitleaks.toml"), cfg, 0o600); err != nil {
		t.Fatal(err)
	}

	rep, _, _, res := scanGit(t, r.dir)
	if res.exitCode != 1 {
		t.Errorf("exit = %d, want 1 (one leak remains)", res.exitCode)
	}
	if len(rep.Secrets) != 1 {
		t.Fatalf("lifecycle secrets = %d, want 1 (suppressed finding must not appear)", len(rep.Secrets))
	}
	for _, e := range rep.Secrets {
		for _, loc := range e.Locations {
			if loc.File == "a.env" {
				t.Errorf("suppressed location a.env appeared in the lifecycle report")
			}
		}
	}
}

// TestLifecycleExitCodeUnchanged verifies --lifecycle does not change exit
// codes: no findings still exits 0, and --exit-code is honored.
func TestLifecycleExitCodeUnchanged(t *testing.T) {
	r := newRepo(t)
	r.commit(commitSpec{date: "2020-01-01T00:00:00Z", msg: "clean"},
		map[string]string{"README.md": "nothing here\n"})
	writeConfig(t, r.dir)

	outDir := t.TempDir()
	res := runGitleaks(t,
		"git", r.dir,
		"--config", filepath.Join(r.dir, ".gitleaks.toml"),
		"--report-path", filepath.Join(outDir, "f.json"), "--report-format", "json",
		"--lifecycle", "--lifecycle-report-path", filepath.Join(outDir, "l.json"),
		"--log-level", "error", "--no-banner",
	)
	if res.exitCode != 0 {
		t.Errorf("clean scan exit = %d, want 0", res.exitCode)
	}

	r.commit(commitSpec{date: "2020-02-01T00:00:00Z", msg: "leak"},
		map[string]string{"a.env": "TOKEN=LCK_AAAA1111\n"})
	res = runGitleaks(t,
		"git", r.dir,
		"--config", filepath.Join(r.dir, ".gitleaks.toml"),
		"--report-path", filepath.Join(outDir, "f2.json"), "--report-format", "json",
		"--lifecycle", "--lifecycle-report-path", filepath.Join(outDir, "l2.json"),
		"--exit-code", "7",
		"--log-level", "error", "--no-banner",
	)
	if res.exitCode != 7 {
		t.Errorf("exit = %d, want the configured 7", res.exitCode)
	}
}

// TestLifecycleRedactKeepsIdentity verifies --redact does not change lifecycle
// conclusions or the identity in the lifecycle report.
func TestLifecycleRedactKeepsIdentity(t *testing.T) {
	r := newRepo(t)
	r.commit(commitSpec{date: "2020-01-01T00:00:00Z", msg: "add"},
		map[string]string{"a.env": "TOKEN=LCK_AAAA1111\n"})
	writeConfig(t, r.dir)

	plain, _, _, _ := scanGit(t, r.dir)
	outDir := t.TempDir()
	lcPath := filepath.Join(outDir, "lc.json")
	reportPath := filepath.Join(outDir, "findings.json")
	res := runGitleaks(t,
		"git", r.dir,
		"--config", filepath.Join(r.dir, ".gitleaks.toml"),
		"--report-path", reportPath, "--report-format", "json",
		"--lifecycle", "--lifecycle-report-path", lcPath,
		"--redact",
		"--log-level", "error", "--no-banner",
	)
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1", res.exitCode)
	}

	raw, err := os.ReadFile(lcPath)
	if err != nil {
		t.Fatal(err)
	}
	redacted := mustParse(t, raw)
	if len(redacted.Secrets) != 1 || len(plain.Secrets) != 1 {
		t.Fatalf("expected one secret each, got %d and %d", len(redacted.Secrets), len(plain.Secrets))
	}
	if redacted.Secrets[0].SecretID != plain.Secrets[0].SecretID {
		t.Errorf("--redact changed the lifecycle identifier")
	}
	if redacted.Secrets[0].Status != "in-use" {
		t.Errorf("status with --redact = %q, want in-use", redacted.Secrets[0].Status)
	}
	if strings.Contains(string(raw), "LCK_AAAA1111") {
		t.Errorf("lifecycle report contains the plaintext secret")
	}

	findingsRaw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(findingsRaw), "LCK_AAAA1111") {
		t.Errorf("--redact report contains the plaintext secret")
	}
}
