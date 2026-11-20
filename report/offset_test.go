package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var offsetFinding = Finding{
	RuleID:      "test-rule",
	Match:       "AKIAIOSFODNN7EXAMPLE",
	Secret:      "AKIAIOSFODNN7EXAMPLE",
	StartLine:   1,
	EndLine:     1,
	StartColumn: 101,
	EndColumn:   120,
	StartOffset: 100,
	EndOffset:   120,
	File:        "firmware.bin",
	Tags:        []string{},
}

// TestWriteJSONOffsets verifies that byte offsets are emitted for
// offset-anchored findings and omitted for findings without them.
func TestWriteJSONOffsets(t *testing.T) {
	reporter := JsonReporter{}

	// With offsets: fields present.
	buf := testWriter{bytes.NewBuffer(nil)}
	require.NoError(t, reporter.Write(buf, []Finding{offsetFinding}))

	var decoded []map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	require.Len(t, decoded, 1)
	assert.Equal(t, float64(100), decoded[0]["StartOffset"])
	assert.Equal(t, float64(120), decoded[0]["EndOffset"])

	// Without offsets: fields omitted (backwards compatible).
	buf = testWriter{bytes.NewBuffer(nil)}
	require.NoError(t, reporter.Write(buf, []Finding{simpleFinding}))
	assert.NotContains(t, buf.String(), "StartOffset")
	assert.NotContains(t, buf.String(), "EndOffset")
}

// TestWriteCSVOffsets verifies that offset columns are appended only
// when findings carry offsets.
func TestWriteCSVOffsets(t *testing.T) {
	reporter := CsvReporter{}

	buf := testWriter{bytes.NewBuffer(nil)}
	require.NoError(t, reporter.Write(buf, []Finding{offsetFinding}))
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 2)
	header := lines[0]
	assert.True(t, strings.HasSuffix(header, "StartOffset,EndOffset"))
	assert.True(t, strings.HasSuffix(lines[1], "100,120"))

	// Without offsets: historical column layout.
	buf = testWriter{bytes.NewBuffer(nil)}
	require.NoError(t, reporter.Write(buf, []Finding{simpleFinding}))
	assert.NotContains(t, buf.String(), "Offset")
}

// TestWriteSarifOffsets verifies that the SARIF region carries a byte
// range when the finding has offsets.
func TestWriteSarifOffsets(t *testing.T) {
	reporter := SarifReporter{}

	buf := testWriter{bytes.NewBuffer(nil)}
	require.NoError(t, reporter.Write(buf, []Finding{offsetFinding}))
	assert.Contains(t, buf.String(), `"byteOffset": 100`)
	assert.Contains(t, buf.String(), `"byteLength": 20`)

	// Without offsets: no byte range.
	buf = testWriter{bytes.NewBuffer(nil)}
	require.NoError(t, reporter.Write(buf, []Finding{simpleFinding}))
	assert.NotContains(t, buf.String(), "byteOffset")
}
