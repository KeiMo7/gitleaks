package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

// TestAllowlistMultiValueIndex verifies that when a field declares several
// values, adjudication can point at the exact declared value that matched,
// not merely the field name. Declaration order is the index basis.
func TestAllowlistMultiValueIndex(t *testing.T) {
	al := &Allowlist{
		Regexes: []*regexp.Regexp{
			regexp.MustCompile(`nomatch-one`),
			regexp.MustCompile(`nomatch-two`),
			regexp.MustCompile(`OLIA`),
			regexp.MustCompile(`nomatch-three`),
		},
		Paths: []*regexp.Regexp{
			regexp.MustCompile(`nope\.go`),
			regexp.MustCompile(`main\.go`),
		},
		StopWords: []string{"word-zero", "word-one", "olia"},
		Commits:   []string{"AAA111", "BBB222"},
	}
	require.NoError(t, al.Validate())

	// Regex: the third declared pattern (index 2) matches.
	ok, idx := al.RegexMatch("token=AKIALALEMEL33243OLIA")
	assert.True(t, ok)
	assert.Equal(t, 2, idx)

	// A non-matching target reports false and -1.
	ok, idx = al.RegexMatch("nothing here")
	assert.False(t, ok)
	assert.Equal(t, -1, idx)

	// Path: second declared pattern (index 1).
	ok, idx = al.PathMatch("src/main.go")
	assert.True(t, ok)
	assert.Equal(t, 1, idx)

	// Stopword: third declared word (index 2), case-insensitive.
	ok, idx = al.StopWordMatch("AKIALALEMEL33243OLIA")
	assert.True(t, ok)
	assert.Equal(t, 2, idx)

	// Commit: second declared commit (index 1), normalized to lower case.
	ok, idx = al.CommitMatch("bbb222")
	assert.True(t, ok)
	assert.Equal(t, 1, idx)
}

// TestAllowlistDedupPreservesOrder verifies Validate keeps a deterministic,
// declaration-ordered unique view even with duplicate declarations.
func TestAllowlistDedupPreservesOrder(t *testing.T) {
	al := &Allowlist{
		Commits:   []string{"CommitA", "commitb", "COMMITA"},
		StopWords: []string{"WordA", "wordb", "worda"},
	}
	require.NoError(t, al.Validate())

	assert.Equal(t, []string{"commita", "commitb"}, al.uniqueCommits)
	assert.Equal(t, []string{"worda", "wordb"}, al.uniqueStopWords)

	// Indices resolve against the order-preserving unique view.
	ok, idx := al.CommitMatch("COMMITB")
	assert.True(t, ok)
	assert.Equal(t, 1, idx)
	ok, idx = al.StopWordMatch("WORDA")
	assert.True(t, ok)
	assert.Equal(t, 0, idx)
}

// TestAllowlistSignatureStable verifies the synonym signature is independent
// of declaration order but sensitive to actual content differences.
func TestAllowlistSignatureStable(t *testing.T) {
	a := &Allowlist{
		Paths:   []*regexp.Regexp{regexp.MustCompile(`a\.go`), regexp.MustCompile(`b\.go`)},
		Commits: []string{"x"},
	}
	b := &Allowlist{
		Paths:   []*regexp.Regexp{regexp.MustCompile(`b\.go`), regexp.MustCompile(`a\.go`)},
		Commits: []string{"x"},
	}
	c := &Allowlist{
		Paths:   []*regexp.Regexp{regexp.MustCompile(`a\.go`), regexp.MustCompile(`c\.go`)},
		Commits: []string{"x"},
	}
	require.NoError(t, a.Validate())
	require.NoError(t, b.Validate())
	require.NoError(t, c.Validate())

	assert.Equal(t, a.Signature(), b.Signature(), "reordering values must not change the signature")
	assert.NotEqual(t, a.Signature(), c.Signature(), "different values must change the signature")
}
