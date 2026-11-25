package detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/report"
)

// stamped builds an allowlist with an explicit provenance stamp so the
// adjudication total order can be asserted deterministically.
func stamped(layer config.AllowlistLayer, ordinal int, al *config.Allowlist) *config.Allowlist {
	if err := al.Validate(); err != nil {
		panic(err)
	}
	al.Stamp = &config.AllowlistStamp{
		ID:         configID(ordinal),
		Ordinal:    ordinal,
		Layer:      layer,
		Scope:      config.AllowlistScopeTargeted,
		ConfigPath: "matrix.toml",
		Kind:       "allowlists",
		Index:      ordinal,
	}
	return al
}

func configID(i int) string {
	return "AL-MATRIX-" + itoa(i)
}

// matrixCase is one cell of the four-layer × two-condition × three-projection
// matrix.
type matrixCase struct {
	name       string
	layer      config.AllowlistLayer
	condition  config.AllowlistMatchCondition
	projection string // secret | match | line
	// regexPattern is declared in the allowlist; it is written to match or not.
	regexPattern string
	// wantSuppress is the expected verdict against the candidate.
	wantSuppress bool
	// wantField is the expected status of the regex field.
	wantFieldStatus string
}

func TestAdjudicationMatrix(t *testing.T) {
	// A fixed candidate exercising all three projections distinctly.
	const (
		secret = "AKIALALEMEL33243OLIA"
		match  = "token=AKIALALEMEL33243OLIA;env=prod"
		line   = "awsToken := \"AKIALALEMEL33243OLIA\" // docs"
	)
	fragment := Fragment{FilePath: "main.go", CommitSHA: "abc123def456"}
	finding := report.Finding{
		RuleID: "matrix-rule",
		File:   "main.go",
		Line:   line,
		Match:  match,
		Secret: secret,
	}

	layers := []struct {
		name  string
		layer config.AllowlistLayer
	}{
		{"builtin", config.AllowlistLayerBuiltin},
		{"extension", config.AllowlistLayerExtension},
		{"global", config.AllowlistLayerGlobal},
		{"rule", config.AllowlistLayerRule},
	}
	conditions := []struct {
		name     string
		cond     config.AllowlistMatchCondition
		orMarker bool
	}{
		{"OR", config.AllowlistMatchOr, true},
		{"AND", config.AllowlistMatchAnd, false},
	}
	projections := []struct {
		name   string
		target string
		// pattern that matches only this projection, not the others.
		matchPattern string
		// a value present only in the line projection.
		lineOnlyPattern string
	}{
		{"secret", "", "AKIALALEMEL33243OLIA", "awsToken"},
		{"match", "match", "token=AKIALALEMEL33243OLIA", "awsToken"},
		{"line", "line", "awsToken", "awsToken"},
	}

	cellCount := 0
	for _, lc := range layers {
		for _, cc := range conditions {
			for _, pc := range projections {
				// Cell 1: a matching regex -> suppress.
				t.Run(lc.name+"/"+cc.name+"/"+pc.name+"/match", func(t *testing.T) {
					cellCount++
					al := &config.Allowlist{
						MatchCondition: cc.cond,
						RegexTarget:    pc.target,
						Regexes:        []*regexp.Regexp{regexp.MustCompile(pc.matchPattern)},
					}
					stamped(lc.layer, cellCount, al)
					ev := evaluateAdjudication(fragment, &finding, line, stageFinding, []*config.Allowlist{al})
					require.Len(t, ev.verdicts, 1)
					assert.True(t, ev.verdicts[0].Suppresses, "matching regex must suppress regardless of layer/condition")
					regexField := fieldByName(ev.verdicts[0].Fields, fieldRegex)
					require.NotNil(t, regexField)
					assert.Equal(t, statusTrue, regexField.Status)
					assert.Equal(t, 0, regexField.ValueIndex, "must point at the declared value index")
					assert.Equal(t, pc.name, regexField.Projection)
					assert.True(t, ev.suppresses)
					require.Len(t, ev.hits, 1)
					assert.Equal(t, lc.layer.String(), ev.hits[0].Layer)
				})

				// Cell 2: a non-matching regex -> retain.
				t.Run(lc.name+"/"+cc.name+"/"+pc.name+"/nomatch", func(t *testing.T) {
					cellCount++
					al := &config.Allowlist{
						MatchCondition: cc.cond,
						RegexTarget:    pc.target,
						Regexes:        []*regexp.Regexp{regexp.MustCompile(`ZZZ-NEVER-PRESENT`)},
					}
					stamped(lc.layer, cellCount, al)
					ev := evaluateAdjudication(fragment, &finding, line, stageFinding, []*config.Allowlist{al})
					require.Len(t, ev.verdicts, 1)
					assert.False(t, ev.verdicts[0].Suppresses)
					regexField := fieldByName(ev.verdicts[0].Fields, fieldRegex)
					require.NotNil(t, regexField)
					assert.Equal(t, statusFalse, regexField.Status)
					assert.False(t, ev.suppresses)
				})
			}
		}
	}

	// Projection isolation: a line-only pattern must match ONLY the line
	// projection and be false on secret/match, so the same candidate is
	// counted once per allowlist (no double counting across projections).
	t.Run("projection isolation line-only", func(t *testing.T) {
		for _, target := range []string{"", "match", "line"} {
			al := &config.Allowlist{
				RegexTarget: target,
				Regexes:     []*regexp.Regexp{regexp.MustCompile("awsToken")},
			}
			stamped(config.AllowlistLayerRule, 99, al)
			ev := evaluateAdjudication(fragment, &finding, line, stageFinding, []*config.Allowlist{al})
			got := ev.verdicts[0].Suppresses
			want := target == "line"
			assert.Equal(t, want, got, "target=%q", target)
		}
	})

	// AND condition field vector: all declared fields must be true; a single
	// false field retains while the individual field statuses stay visible.
	t.Run("AND vector requires every declared field", func(t *testing.T) {
		al := &config.Allowlist{
			MatchCondition: config.AllowlistMatchAnd,
			Paths:          []*regexp.Regexp{regexp.MustCompile(`main\.go`)},
			StopWords:      []string{"missing-word"},
		}
		stamped(config.AllowlistLayerRule, 7, al)
		ev := evaluateAdjudication(fragment, &finding, line, stageFinding, []*config.Allowlist{al})
		v := ev.verdicts[0]
		assert.False(t, v.Suppresses)
		assert.Equal(t, statusTrue, fieldByName(v.Fields, fieldPath).Status)
		assert.Equal(t, statusFalse, fieldByName(v.Fields, fieldStopword).Status)
	})

	// Undeclared vs unavailable must never collapse into false.
	t.Run("not-declared vs not-applicable", func(t *testing.T) {
		// No commit input on the fragment: a declared commit field is N/A.
		noCommit := fragment
		noCommit.CommitSHA = ""
		al := &config.Allowlist{Commits: []string{"abc123def456"}}
		stamped(config.AllowlistLayerGlobal, 3, al)
		ev := evaluateAdjudication(noCommit, &finding, line, stageFinding, []*config.Allowlist{al})
		commitField := fieldByName(ev.verdicts[0].Fields, fieldCommit)
		assert.Equal(t, statusNotApplicable, commitField.Status, "missing input is N/A, not false")
		// An allowlist without regexes keeps regex not-declared.
		al2 := &config.Allowlist{Paths: []*regexp.Regexp{regexp.MustCompile("main.go")}}
		stamped(config.AllowlistLayerGlobal, 4, al2)
		ev2 := evaluateAdjudication(fragment, &finding, line, stageFinding, []*config.Allowlist{al2})
		assert.Equal(t, statusNotDeclared, fieldByName(ev2.verdicts[0].Fields, fieldRegex).Status)
	})
}

func fieldByName(fields []FieldVerdict, name string) *FieldVerdict {
	for i := range fields {
		if fields[i].Field == name {
			return &fields[i]
		}
	}
	return nil
}

// TestAdjudicationTotalOrder asserts the layer priority total order is
// independent of slice order and lists every simultaneous hitter.
func TestAdjudicationTotalOrder(t *testing.T) {
	fragment := Fragment{FilePath: "main.go"}
	finding := report.Finding{RuleID: "r", File: "main.go", Secret: "AKIALALEMEL33243OLIA", Match: "AKIALALEMEL33243OLIA"}

	build := func() []*config.Allowlist {
		rule := stamped(config.AllowlistLayerRule, 4, &config.Allowlist{StopWords: []string{"olia"}})
		global := stamped(config.AllowlistLayerGlobal, 3, &config.Allowlist{StopWords: []string{"akia"}})
		ext := stamped(config.AllowlistLayerExtension, 2, &config.Allowlist{StopWords: []string{"alem"}})
		builtin := stamped(config.AllowlistLayerBuiltin, 1, &config.Allowlist{StopWords: []string{"akial"}})
		return []*config.Allowlist{global, builtin, rule, ext} // intentionally shuffled
	}

	ev := evaluateAdjudication(fragment, &finding, finding.Line, stageFinding, build())
	assert.True(t, ev.suppresses)
	require.NotNil(t, ev.adjudicator)
	assert.Equal(t, "rule", ev.adjudicator.Layer, "rule layer wins regardless of slice order")
	wantOrder := []string{"rule", "global", "extension", "builtin"}
	gotLayers := make([]string, 0, len(ev.hits))
	gotIDs := make([]string, 0, len(ev.hits))
	for _, h := range ev.hits {
		gotLayers = append(gotLayers, h.Layer)
		gotIDs = append(gotIDs, h.AllowlistID)
	}
	assert.Equal(t, wantOrder, gotLayers)
	assert.Len(t, gotIDs, 4, "all four simultaneous hitters must be listed")
}
