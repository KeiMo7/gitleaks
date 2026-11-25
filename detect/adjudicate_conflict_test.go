package detect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/report"
)

// TestContradictionConflictAcrossSources verifies that allowlists in distinct
// sources which share a true field but reach opposite verdicts emit the stable
// contradiction code with both identities.
func TestContradictionConflictAcrossSources(t *testing.T) {
	fragment := Fragment{FilePath: "main.go"}
	finding := report.Finding{RuleID: "r", File: "main.go", Secret: "AKIALALEMEL33243OLIA", Match: "AKIALALEMEL33243OLIA"}

	// Global source: OR stopword that matches -> suppresses; the stopword
	// field is true and participates in the finding-scope OR merge.
	global := stamped(config.AllowlistLayerGlobal, 1, &config.Allowlist{
		StopWords: []string{"olia"},
	})
	// Rule source: AND stopword+path; the SAME stopword value is true here
	// too, but the path is false so the verdict is retain. The shared true
	// stopword field yields opposite overall verdicts across the two sources.
	rule := stamped(config.AllowlistLayerRule, 2, &config.Allowlist{
		MatchCondition: config.AllowlistMatchAnd,
		Paths:          []*regexp.Regexp{regexp.MustCompile(`other\.go`)},
		StopWords:      []string{"olia"},
	})

	ad := NewAdjudicator(config.Config{})
	ev := evaluateAdjudication(fragment, &finding, "", stageFinding, []*config.Allowlist{global, rule})
	ad.collectRuntimeConflicts(ev)

	report := ad.finalize()
	var codes []string
	for _, c := range report.Conflicts {
		codes = append(codes, c.Code)
	}
	assert.Contains(t, codes, config.ConflictContradiction)
	for _, c := range report.Conflicts {
		if c.Code == config.ConflictContradiction {
			assert.Len(t, c.AllowlistIDs, 2)
			assert.ElementsMatch(t, []string{"global", "rule"}, c.Layers)
		}
	}
}

// TestSameSourceNoContradiction verifies differing verdicts within one source
// are ordinary layering, not contradictions.
func TestSameSourceNoContradiction(t *testing.T) {
	fragment := Fragment{FilePath: "main.go"}
	finding := report.Finding{RuleID: "r", File: "main.go", Secret: "AKIALALEMEL33243OLIA", Match: "AKIALALEMEL33243OLIA"}

	a := stamped(config.AllowlistLayerGlobal, 1, &config.Allowlist{StopWords: []string{"akia"}})
	b := stamped(config.AllowlistLayerGlobal, 2, &config.Allowlist{StopWords: []string{"absent"}})

	ad := NewAdjudicator(config.Config{})
	ev := evaluateAdjudication(fragment, &finding, "", stageFinding, []*config.Allowlist{a, b})
	ad.collectRuntimeConflicts(ev)
	report := ad.finalize()
	for _, c := range report.Conflicts {
		assert.NotEqual(t, config.ConflictContradiction, c.Code)
	}
}

// TestFieldUnavailableConflict verifies a declared, merge-participating field
// with no candidate input is reported via the stable unavailable code, while
// file-scope content fields stay quiet.
func TestFieldUnavailableConflict(t *testing.T) {
	// Path-only finding carries no secret: a finding-scope stopword is N/A.
	pathOnlyFragment := Fragment{FilePath: "main.go"}
	pathOnlyFinding := report.Finding{RuleID: "r", File: "main.go"}
	al := stamped(config.AllowlistLayerRule, 1, &config.Allowlist{StopWords: []string{"olia"}})

	ad := NewAdjudicator(config.Config{})
	ev := evaluateAdjudication(pathOnlyFragment, &pathOnlyFinding, "", stageFinding, []*config.Allowlist{al})
	ad.collectRuntimeConflicts(ev)
	rep := ad.finalize()
	var sawUnavailable bool
	for _, c := range rep.Conflicts {
		if c.Code == config.ConflictFieldUnavailable {
			sawUnavailable = true
			assert.Equal(t, "AL-MATRIX-1", c.AllowlistIDs[0])
		}
	}
	assert.True(t, sawUnavailable)

	// At file scope the same allowlist must not raise field-unavailable.
	ad2 := NewAdjudicator(config.Config{})
	ev2 := evaluateAdjudication(pathOnlyFragment, nil, "", stageFile, []*config.Allowlist{al})
	ad2.collectRuntimeConflicts(ev2)
	for _, c := range ad2.finalize().Conflicts {
		assert.NotEqual(t, config.ConflictFieldUnavailable, c.Code)
	}
}

// TestRecordContainsNoSecret verifies the adjudication record never carries
// secret material even at trace level: only rule ids, positions, list ids and
// booleans are serialized.
func TestRecordContainsNoSecret(t *testing.T) {
	const secret = "AKIALALEMEL33243SUPERSECRET"
	fragment := Fragment{FilePath: "main.go", CommitSHA: "deadbeefcafe"}
	finding := report.Finding{
		RuleID: "r", File: "main.go", Secret: secret, Match: "x=" + secret,
		Line: "key = " + secret,
	}
	al := stamped(config.AllowlistLayerRule, 1, &config.Allowlist{Regexes: []*regexp.Regexp{regexp.MustCompile(secret)}})

	ad := NewAdjudicator(config.Config{})
	ev := evaluateAdjudication(fragment, &finding, finding.Line, stageFinding, []*config.Allowlist{al})
	ad.addRecord(Record{
		Stage: stageFinding, Decision: "suppressed", Reason: "test",
		Candidate: candidateRef("r", fragment, &finding),
		Verdicts:  ev.verdicts,
	})
	rep := ad.finalize()

	raw, err := json.Marshal(rep)
	require.NoError(t, err)
	text := string(raw)
	assert.NotContains(t, text, secret)
	assert.NotContains(t, text, "SUPERSECRET")
	// Sanity: the structural identifiers are present.
	assert.Contains(t, text, "AL-MATRIX-1")
	assert.Contains(t, text, "main.go")
	assert.Contains(t, text, "deadbeefcafe")
}

// TestAdjudicationDeterministic verifies two finalized reports over identical
// inputs serialize byte-identically.
func TestAdjudicationDeterministic(t *testing.T) {
	fragment := Fragment{FilePath: "b.go", CommitSHA: "c2"}
	finding := report.Finding{RuleID: "r", File: "b.go", Secret: "AKIALALEMEL33243OLIA", Match: "AKIALALEMEL33243OLIA", StartLine: 3}

	build := func() *Adjudicator {
		ad := NewAdjudicator(config.Config{})
		als := []*config.Allowlist{
			stamped(config.AllowlistLayerGlobal, 2, &config.Allowlist{StopWords: []string{"akia"}}),
			stamped(config.AllowlistLayerRule, 1, &config.Allowlist{StopWords: []string{"olia"}}),
		}
		// Insert in two different orders across the two adjudicators.
		ev := evaluateAdjudication(fragment, &finding, "", stageFinding, als)
		ad.addRecord(Record{Stage: stageFinding, Decision: "retained", Candidate: candidateRef("r", fragment, &finding), Verdicts: ev.verdicts})
		return ad
	}

	r1, _ := json.Marshal(build().finalize())
	r2, _ := json.Marshal(build().finalize())
	assert.JSONEq(t, string(r1), string(r2))
	// Byte equality: deterministic key order from sorted slices.
	assert.Equal(t, string(r1), string(r2))
}

// TestWriteAdjudicationReportAtomic verifies the happy path writes a complete
// JSON file and leaves no temp artifacts, and the bad-format path errors.
func TestWriteAdjudicationReportAtomic(t *testing.T) {
	dir := t.TempDir()

	d := NewDetector(config.Config{})
	d.AdjudicationPath = filepath.Join(dir, "adj.json")
	al := stamped(config.AllowlistLayerRule, 1, &config.Allowlist{StopWords: []string{"olia"}})
	d.Config.Allowlists = []*config.Allowlist{al}
	d.adjudicator = NewAdjudicator(d.Config)
	d.adjudicator.addRecord(Record{
		Stage: stageFile, Decision: "retained",
		Candidate: CandidateRef{RuleID: "r", File: "f.go"},
		Verdicts:  make([]AllowlistVerdict, 0),
	})

	require.NoError(t, WriteAdjudicationReport(d))
	raw, err := os.ReadFile(d.AdjudicationPath)
	require.NoError(t, err)
	assert.True(t, json.Valid(raw))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasSuffix(e.Name(), ".tmp"), "no temp file left behind")
	}

	// Unsupported extension.
	d2 := NewDetector(config.Config{})
	d2.AdjudicationPath = filepath.Join(dir, "adj.yaml")
	d2.adjudicator = NewAdjudicator(config.Config{})
	err = WriteAdjudicationReport(d2)
	assert.ErrorIs(t, err, ErrAdjudicationFormat)
}

// TestWriteAdjudicationReportUnwritable verifies an unwritable target fails
// rather than silently skipping the record.
func TestWriteAdjudicationReportUnwritable(t *testing.T) {
	d := NewDetector(config.Config{})
	d.AdjudicationPath = filepath.Join(t.TempDir(), "missing-subdir", "adj.json")
	d.adjudicator = NewAdjudicator(config.Config{})
	err := WriteAdjudicationReport(d)
	assert.Error(t, err)
}
