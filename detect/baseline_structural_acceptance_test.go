package detect

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/report"
)

// bufWC is an in-memory io.WriteCloser for report reporters.
type bufWC struct{ *bytes.Buffer }

func (bufWC) Close() error { return nil }

func canonicalFinding() report.Finding {
	return report.Finding{
		RuleID:      "acme-token",
		Description: "Acme API token",
		StartLine:   42,
		EndLine:     42,
		StartColumn: 11,
		EndColumn:   47,
		Match:       `acme_token = "acme_live_abcdef1234567890"`,
		Secret:      "acme_live_abcdef1234567890",
		File:        "services/payments/config.go",
		Commit:      "0123456789abcdef0123456789abcdef01234567",
		Author:      "Ada Lovelace",
		Email:       "ada@example.com",
		Date:        "2026-01-02T03:04:05Z",
		Message:     "initial commit",
		Tags:        []string{"acme", "api"},
		Fingerprint: "0123456789abcdef0123456789abcdef01234567:services/payments/config.go:acme-token:42",
		Entropy:     4.123456,
	}
}

func mutate(f report.Finding, fn func(*report.Finding)) report.Finding {
	fn(&f)
	return f
}

// TestStructuralMutationsMustNotRevive locks requirement I.3: cosmetic drift
// never makes an existing baseline entry new again.
func TestStructuralMutationsMustNotRevive(t *testing.T) {
	t.Parallel()
	base := canonicalFinding()
	baseline := []report.Finding{base}

	cases := map[string]report.Finding{
		"description rewritten": mutate(base, func(f *report.Finding) {
			f.Description = "Completely new rule wording for Acme tokens"
		}),
		"tags reordered and extended": mutate(base, func(f *report.Finding) {
			f.Tags = []string{"api", "extra", "acme"}
		}),
		"entropy float tail noise": mutate(base, func(f *report.Finding) {
			f.Entropy = base.Entropy + 0.0000001
		}),
		"date written differently": mutate(base, func(f *report.Finding) {
			f.Date = "January 2nd, 2026 03:04 UTC"
		}),
		"missing description": mutate(base, func(f *report.Finding) { f.Description = "" }),
		"missing entropy":     mutate(base, func(f *report.Finding) { f.Entropy = 0 }),
		"missing commit metadata (dir scan)": mutate(base, func(f *report.Finding) {
			f.Commit, f.Author, f.Email, f.Date, f.Message = "", "", "", "", ""
			f.Fingerprint = "services/payments/config.go:acme-token:42"
		}),
	}

	for name, got := range cases {
		t.Run(name, func(t *testing.T) {
			assert.False(t, IsNew(got, 0, baseline), "mutated entry must stay baselined: %s", name)
		})
	}
}

// TestStructuralNegativeCases ensures the overlay does not over-match.
func TestStructuralNegativeCases(t *testing.T) {
	t.Parallel()
	base := canonicalFinding()
	baseline := []report.Finding{base}

	cases := map[string]report.Finding{
		"different rule": mutate(base, func(f *report.Finding) { f.RuleID = "other-token" }),
		"different line": mutate(base, func(f *report.Finding) { f.StartLine = 43 }),
		"different file": mutate(base, func(f *report.Finding) { f.File = "services/billing/config.go" }),
		"rotated unmasked secret": mutate(base, func(f *report.Finding) {
			f.Secret = "acme_live_ROTATED0000000000"
		}),
		"both commits present but different": mutate(base, func(f *report.Finding) {
			f.Commit = "ffffffffffffffffffffffffffffffffffffffff"
		}),
	}
	for name, got := range cases {
		t.Run(name, func(t *testing.T) {
			assert.True(t, IsNew(got, 0, baseline), "expected %q to be new", name)
		})
	}
}

func TestPathForms(t *testing.T) {
	t.Parallel()
	pairs := [][2]string{
		{"svc/a.go", "svc/a.go"},
		{"./svc/a.go", "svc/a.go"},
		{"svc/a.go", "/repo/svc/a.go"},
		{"/repo/svc/a.go", "/ci/workspace/clone/svc/a.go"},
		{`svc\a.go`, "svc/a.go"},
		{`C:\repo\svc\a.go`, "/repo/svc/a.go"},
		{"/repo/svc/a.go", `C:\repo\svc\a.go`},
		{"a.go", "/very/deep/a.go"},
	}
	for _, p := range pairs {
		assert.True(t, sameFilePath(p[0], p[1]), "expected paths to match: %q vs %q", p[0], p[1])
	}

	notPairs := [][2]string{
		{"svc/a.go", "svc/b.go"},
		{"config/prod.yml", "config/dev.yml"},
		{"", "svc/a.go"},
		{"svc/a.go", ""},
	}
	for _, p := range notPairs {
		assert.False(t, sameFilePath(p[0], p[1]), "expected paths NOT to match: %q vs %q", p[0], p[1])
	}
}

func TestDoesNotRelaxToAnyLine(t *testing.T) {
	t.Parallel()
	b := canonicalFinding()
	other := b
	other.StartLine = 999
	assert.True(t, IsNew(other, 0, []report.Finding{b}))
}

func TestMaskedBaselineMatching(t *testing.T) {
	t.Parallel()
	raw := canonicalFinding()

	fullMasked := mutate(raw, func(f *report.Finding) {
		f.Secret = "************************"
		f.Match = "****************************************"
	})
	assert.False(t, IsNew(raw, 0, []report.Finding{fullMasked}), "fully masked -> rule+location")

	redactedToken := mutate(raw, func(f *report.Finding) {
		f.Secret = "REDACTED"
	})
	assert.False(t, IsNew(raw, 100, []report.Finding{redactedToken}))

	partial := mutate(raw, func(f *report.Finding) {
		f.Secret = raw.Secret[:6] + "..."
	})
	assert.False(t, IsNew(raw, 0, []report.Finding{partial}), "visible prefix matches")

	wrongPrefix := mutate(raw, func(f *report.Finding) {
		f.Secret = "zzzzzz..."
	})
	assert.True(t, IsNew(raw, 0, []report.Finding{wrongPrefix}), "different visible prefix is a rotated secret")

	// Unmasked baseline demands full content equality.
	rotated := raw
	rotated.Secret = raw.Secret + "extra"
	assert.True(t, IsNew(rotated, 0, []report.Finding{raw}))
}

func TestFingerprintOnlyEntry(t *testing.T) {
	t.Parallel()
	fpOnly := report.Finding{Fingerprint: canonicalFinding().Fingerprint}
	// Decidable through fingerprint parsing.
	assert.True(t, Decidable(fpOnly))
	live := canonicalFinding()
	live.Description = "changed"
	assert.False(t, IsNew(live, 0, []report.Finding{fpOnly}))

	globalFP := report.Finding{Fingerprint: "services/payments/config.go:acme-token:42"}
	assert.True(t, Decidable(globalFP))
	live.Commit = ""
	live.Fingerprint = globalFP.Fingerprint
	assert.False(t, IsNew(live, 0, []report.Finding{globalFP}))
}

// TestFourFormatRoundTrip writes reports with the real reporters and imports
// them as baselines.
func TestFourFormatRoundTrip(t *testing.T) {
	t.Parallel()
	findings := []report.Finding{canonicalFinding()}

	reporters := map[string]report.Reporter{
		"json":  &report.JsonReporter{},
		"csv":   &report.CsvReporter{},
		"sarif": &report.SarifReporter{},
		"junit": &report.JunitReporter{},
	}

	for name, rep := range reporters {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			wc := bufWC{&buf}
			require.NoError(t, rep.Write(wc, findings))

			loaded, err := ParseBaseline(buf.Bytes())
			require.NoError(t, err)
			require.Len(t, loaded, 1)

			live := canonicalFinding()
			// Simulate format-specific information loss.
			if name == "sarif" {
				live.Match = "" // SARIF only carries the secret snippet
			}
			assert.False(t, IsNew(live, 0, loaded), "%s baseline must suppress identical entry", name)
		})
	}
}

func TestContentSniffingIgnoresExtension(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	findings := []report.Finding{canonicalFinding()}

	cases := map[string]struct {
		reporter report.Reporter
		filename string // deliberately wrong extension
	}{
		"json named .txt":  {&report.JsonReporter{}, "baseline.txt"},
		"csv named .json":  {&report.CsvReporter{}, "baseline.json"},
		"sarif named .log": {&report.SarifReporter{}, "baseline.log"},
		"junit named .xml": {&report.JunitReporter{}, "baseline.dat"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			require.NoError(t, tc.reporter.Write(bufWC{&buf}, findings))
			p := filepath.Join(dir, tc.filename)
			require.NoError(t, os.WriteFile(p, buf.Bytes(), 0o600))

			loaded, err := LoadBaseline(p)
			require.NoError(t, err)
			require.Len(t, loaded, 1)
		})
	}
}

func TestExceptionalInputs(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		content string
		wantErr bool
	}{
		"zero bytes":             {"", false},
		"whitespace only":        {"  \n\t", false},
		"empty json array":       {"[]", false},
		"empty sarif run set":    {`{"version":"2.1.0","runs":[]}`, false},
		"header only csv":        {"RuleID,File,StartLine\n", false},
		"empty junit":            {`<?xml version="1.0"?><testsuites></testsuites>`, false},
		"truncated json":         {`[{"RuleID":"x"`, true},
		"truncated sarif":        {`{"runs":[{"results":[{"ruleId":"x"`, true},
		"truncated junit":        {`<testsuites><testsuite><testcase>`, true},
		"custom template text":   {"# Report\n{{ range . }}{{ .Secret }}{{ end }}\n", true},
		"unrecognized json obj":  {`{"hello":"world"}`, true},
		"undecidable json entry": {`[{"Description":"no id or file"}]`, true},
		"csv missing key header": {"Foo,Bar\n1,2\n", true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fs, err := ParseBaseline([]byte(tc.content))
			if tc.wantErr {
				require.Error(t, err, "expected explicit failure for %s", name)
				var bie *BaselineImportError
				if strings.Contains(name, "undecidable") {
					require.ErrorAs(t, err, &bie)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, fs)
			}
		})
	}
}

func TestTruncatedSarifErrorLocatesEntryAndField(t *testing.T) {
	t.Parallel()
	_, err := ParseBaseline([]byte(`{"version":"2.1.0","runs":[{"results":[{"ruleId":"x"`))
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "sarif")
	assert.Contains(t, msg, "results[0]")
	assert.Contains(t, msg, "ruleId")
}

func TestMergeIsOrderIndependentAndDedupes(t *testing.T) {
	t.Parallel()
	a := canonicalFinding()
	b := canonicalFinding()
	b.Description = "old"
	b.Entropy = 9.9

	other := canonicalFinding()
	other.RuleID = "other-rule"
	other.Fingerprint = "x/y.go:other-rule:1"
	other.StartLine = 1

	m1 := MergeBaselines([]report.Finding{a}, []report.Finding{b, other})
	m2 := MergeBaselines([]report.Finding{other, b}, []report.Finding{a})

	assert.Len(t, m1, 2, "duplicates folded")
	assert.Equal(t, m1, m2, "merge order independent")

	// Richer representative wins.
	for _, f := range m1 {
		if f.RuleID == a.RuleID {
			assert.Equal(t, a.Description, f.Description)
		}
	}
}

func TestMergeEqualRichnessOrderIndependent(t *testing.T) {
	t.Parallel()
	a := report.Finding{RuleID: "r", File: "f.go", StartLine: 1, Author: "Ann"}
	b := report.Finding{RuleID: "r", File: "f.go", StartLine: 1, Email: "a@x"}

	m1 := MergeBaselines([]report.Finding{a, b})
	m2 := MergeBaselines([]report.Finding{b, a})
	require.Len(t, m1, 1)
	require.Len(t, m2, 1)
	assert.Equal(t, m1[0], m2[0])
	// Complementary fields are united in the representative.
	assert.Equal(t, "Ann", m1[0].Author)
	assert.Equal(t, "a@x", m1[0].Email)
}

func TestFileLessStdinEntry(t *testing.T) {
	t.Parallel()
	stdin := report.Finding{RuleID: "aws-access-token", StartLine: 1, Fingerprint: ":aws-access-token:1"}
	assert.True(t, Decidable(stdin))

	live := stdin
	live.Secret = "AKIALALEMEL33243OKIA"
	base := stdin
	base.Secret = "AKIALALEMEL33243OKIA"
	assert.False(t, IsNew(live, 0, []report.Finding{base}), "file-less stdin entries match each other")

	located := live
	located.File = "app.py"
	assert.True(t, IsNew(located, 0, []report.Finding{base}), "file-less baseline must not match an on-disk finding")
}

func TestLoadBaselinesAggregatesBadSource(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	require.NoError(t, os.WriteFile(good, []byte("[]"), 0o600))
	bad := filepath.Join(dir, "bad.txt")
	require.NoError(t, os.WriteFile(bad, []byte("not a report"), 0o600))

	merged, err := LoadBaselines([]string{good, bad})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad.txt")
	// Good source still contributes; error prevents silent continuation at
	// the CLI layer.
	assert.NotNil(t, merged)
}
