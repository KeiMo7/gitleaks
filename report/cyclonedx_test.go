package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCycloneDXNormalInventoryAndSchema(t *testing.T) {
	findings := []Finding{
		{
			RuleID:    "AWS-Key",
			Commit:    "DeadBEEF",
			File:      "src/MyPkg/Auth.go",
			Secret:    "secret-value",
			StartLine: 10,
			Date:      "2024-01-02T03:04:05Z",
		},
	}

	raw, bom := writeAndDecodeCycloneDX(t, findings)
	validateCycloneDXSchema(t, raw)

	require.Len(t, bom.Components, 4)
	component := requireCycloneDXComponent(t, bom, "AWS-Key", "DeadBEEF")
	assert.Equal(t, "data", component.Type)
	assert.Equal(t, "pkg:generic/src/MyPkg/Auth.go/AWS-Key@DeadBEEF", component.PURL)
	assert.Equal(t, component.PURL, component.BOMRef)
	assert.NotEmpty(t, bom.Metadata.Component.Name)
	assert.NotEmpty(t, bom.Metadata.Component.Version)
	assert.NotEmpty(t, bom.Metadata.Component.PURL)
	assert.NotEmpty(t, bom.Metadata.Component.Type)

	assert.Less(
		t,
		bytes.Index(raw, []byte(`"name":"AWS-Key"`)),
		bytes.Index(raw, []byte(`"version":"DeadBEEF"`)),
	)
	assert.Less(
		t,
		bytes.Index(raw, []byte(`"version":"DeadBEEF"`)),
		bytes.Index(raw, []byte(`"purl":"pkg:generic/src/MyPkg/Auth.go/AWS-Key@DeadBEEF"`)),
	)
}

func TestCycloneDXMissingMetadataIsExplicitAndCounted(t *testing.T) {
	findings := []Finding{
		{Secret: "missing-everything"},
	}

	raw, bom := writeAndDecodeCycloneDX(t, findings)
	validateCycloneDXSchema(t, raw)

	require.Len(t, bom.Components, 1)
	component := bom.Components[0]
	assert.Equal(t, "unknown", component.Name)
	assert.Equal(t, "unknown", component.Version)
	assert.Equal(t, "pkg:generic/unknown/unknown@unknown", component.PURL)
	assert.Equal(t, "data", component.Type)
	assert.True(t, hasCycloneDXProperty(component.Properties, "gitleaks:missing-metadata", "name,source,version"))

	assert.True(t, hasCycloneDXProperty(bom.Metadata.Properties, "gitleaks:missing-name", "1"))
	assert.True(t, hasCycloneDXProperty(bom.Metadata.Properties, "gitleaks:missing-version", "1"))
	assert.True(t, hasCycloneDXProperty(bom.Metadata.Properties, "gitleaks:missing-source", "1"))
	assert.True(t, hasCycloneDXProperty(bom.Metadata.Properties, "gitleaks:missing-metadata-total", "3"))
}

func TestCycloneDXMultipleVersionsRemainSeparate(t *testing.T) {
	findings := []Finding{
		{RuleID: "pkg-token", Commit: "v2", File: "pkg/Module.go", Secret: "secret-v2"},
		{RuleID: "pkg-token", Commit: "v1", File: "pkg/Module.go", Secret: "secret-v1"},
	}

	raw, bom := writeAndDecodeCycloneDX(t, findings)
	validateCycloneDXSchema(t, raw)

	var versions []string
	for _, component := range bom.Components {
		if component.Name == "pkg-token" {
			versions = append(versions, component.Version)
		}
	}
	assert.ElementsMatch(t, []string{"v1", "v2"}, versions)
	requireCycloneDXComponent(t, bom, "pkg-token", "v1")
	requireCycloneDXComponent(t, bom, "pkg-token", "v2")
}

func TestCycloneDXHistoricalSecretMergesAndKeepsFirstCommit(t *testing.T) {
	findings := []Finding{
		{
			RuleID:    "shared-secret",
			Commit:    "newer",
			File:      "src/shared.go",
			Secret:    "same-secret",
			StartLine: 20,
			Date:      "2024-04-01T00:00:00Z",
		},
		{
			RuleID:    "shared-secret",
			Commit:    "older",
			File:      "src/shared.go",
			Secret:    "same-secret",
			StartLine: 10,
			Date:      "2024-01-01T00:00:00Z",
		},
	}

	raw, bom := writeAndDecodeCycloneDX(t, findings)
	validateCycloneDXSchema(t, raw)

	component := requireCycloneDXComponent(t, bom, "shared-secret", "older")
	assert.True(t, hasCycloneDXProperty(component.Properties, "gitleaks:occurrence-count", "2"))
	assert.True(t, hasCycloneDXProperty(component.Properties, "gitleaks:first-introduced-commit", "older"))
	assert.True(t, hasCycloneDXProperty(component.Properties, "gitleaks:first-introduced-date", "2024-01-01T00:00:00Z"))
	assert.NotContains(t, string(raw), "same-secret")
}

func TestCycloneDXDeduplicatesByTupleNotName(t *testing.T) {
	findings := []Finding{
		{RuleID: "duplicate", Commit: "v1", File: "src/a.go", Secret: "one", StartLine: 1},
		{RuleID: "duplicate", Commit: "v1", File: "src/a.go", Secret: "two", StartLine: 2},
		{RuleID: "duplicate", Commit: "v2", File: "src/a.go", Secret: "three", StartLine: 3},
	}

	raw, bom := writeAndDecodeCycloneDX(t, findings)
	validateCycloneDXSchema(t, raw)

	component := requireCycloneDXComponent(t, bom, "duplicate", "v1")
	assert.True(t, hasCycloneDXProperty(component.Properties, "gitleaks:occurrence-count", "2"))
	assert.Equal(t, 2, countCycloneDXProperties(component.Properties, "gitleaks:secret-sha256"))
	requireCycloneDXComponent(t, bom, "duplicate", "v2")
}

func TestCycloneDXDependencyHierarchy(t *testing.T) {
	findings := []Finding{
		{RuleID: "token-a", Commit: "v1", File: "src/MyPkg/Auth.go", Secret: "a"},
		{RuleID: "token-b", Commit: "v1", File: "src/main.go", Secret: "b"},
	}

	raw, bom := writeAndDecodeCycloneDX(t, findings)
	validateCycloneDXSchema(t, raw)

	dependencies := cycloneDXDependenciesByRef(bom)
	assert.Contains(t, dependencies[bom.Metadata.Component.BOMRef], "pkg:generic/gitleaks-path/src@unknown")
	assert.Contains(t, dependencies["pkg:generic/gitleaks-path/src@unknown"], "pkg:generic/gitleaks-path/src/MyPkg@unknown")
	assert.Contains(t, dependencies["pkg:generic/gitleaks-path/src@unknown"], "pkg:generic/gitleaks-path/src/main.go@unknown")
	assert.Contains(t,
		dependencies["pkg:generic/gitleaks-path/src/MyPkg@unknown"],
		"pkg:generic/gitleaks-path/src/MyPkg/Auth.go@unknown",
	)
	assert.Contains(t, dependencies["pkg:generic/gitleaks-path/src/MyPkg/Auth.go@unknown"], "pkg:generic/src/MyPkg/Auth.go/token-a@v1")
	assert.Contains(t, dependencies["pkg:generic/gitleaks-path/src/main.go@unknown"], "pkg:generic/src/main.go/token-b@v1")
}

func TestCycloneDXPURLPreservesCaseAndEscapesUnicode(t *testing.T) {
	findings := []Finding{
		{
			RuleID: "MixedCaseToken",
			Commit: "提交",
			File:   "src/命名空间/组件.go",
			Secret: "unicode-secret",
		},
	}

	raw, bom := writeAndDecodeCycloneDX(t, findings)
	validateCycloneDXSchema(t, raw)

	component := requireCycloneDXComponent(t, bom, "MixedCaseToken", "提交")
	assert.Equal(
		t,
		"pkg:generic/src/%E5%91%BD%E5%90%8D%E7%A9%BA%E9%97%B4/%E7%BB%84%E4%BB%B6.go/MixedCaseToken@%E6%8F%90%E4%BA%A4",
		component.PURL,
	)
	assert.True(t, json.Valid(raw))
}

func TestCycloneDXOutputIsByteStableAcrossFindingOrder(t *testing.T) {
	findings := []Finding{
		{RuleID: "rule-z", Commit: "v3", File: "src/z.go", Secret: "z", Date: "2024-01-03T00:00:00Z"},
		{RuleID: "rule-a", Commit: "v1", File: "src/a.go", Secret: "a", Date: "2024-01-01T00:00:00Z"},
		{RuleID: "rule-m", Commit: "v2", File: "src/m.go", Secret: "m", Date: "2024-01-02T00:00:00Z"},
	}
	reversed := []Finding{findings[2], findings[1], findings[0]}

	first := writeCycloneDXBytes(t, findings)
	second := writeCycloneDXBytes(t, reversed)
	assert.Equal(t, first, second)
}

func TestCycloneDXWriteFailureNamesComponent(t *testing.T) {
	writer := &failOnWriteCloser{failAt: 4}
	err := NewCycloneDXReporter().Write(writer, []Finding{
		{RuleID: "aaa-failing-component", Commit: "v1", File: "zzz/fail.go", Secret: "failure"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `component "aaa-failing-component"`)
}

func TestCycloneDXLargeInputAndNoRetainedState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large CycloneDX report test in short mode")
	}

	findings := make([]Finding, 5000)
	for i := range findings {
		findings[i] = Finding{
			RuleID:    "rule-" + strconv.Itoa(i%100),
			Commit:    "commit-" + strconv.Itoa(i),
			File:      fmt.Sprintf("src/pkg%02d/file%04d.go", i%50, i),
			Secret:    fmt.Sprintf("secret-%d", i),
			StartLine: i + 1,
		}
	}

	reporter := NewCycloneDXReporter()
	writer := &discardWriteCloser{}
	require.NoError(t, reporter.Write(writer, findings))

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < 10; i++ {
		require.NoError(t, reporter.Write(&discardWriteCloser{}, findings))
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	const retainedStateLimit = 16 * 1024 * 1024
	if after.HeapAlloc > before.HeapAlloc+retainedStateLimit {
		t.Fatalf("retained heap grew by %d bytes after repeated reports", after.HeapAlloc-before.HeapAlloc)
	}
	t.Logf("retained heap delta after 10 reports: %d bytes", int64(after.HeapAlloc)-int64(before.HeapAlloc))
}

func TestCycloneDXReporterLeavesTempDirectoryClean(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("TMPDIR", tempDir)

	require.NoError(t, NewCycloneDXReporter().Write(
		&discardWriteCloser{},
		[]Finding{{RuleID: "normal", Commit: "v1", File: "src/normal.go", Secret: "normal"}},
	))
	require.Error(t, NewCycloneDXReporter().Write(
		&failOnWriteCloser{failAt: 2},
		[]Finding{{RuleID: "failure", Commit: "v1", File: "src/failure.go", Secret: "failure"}},
	))

	entries, err := os.ReadDir(tempDir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func writeAndDecodeCycloneDX(t *testing.T, findings []Finding) ([]byte, *CycloneDXBOM) {
	t.Helper()
	raw := writeCycloneDXBytes(t, findings)
	var bom CycloneDXBOM
	require.NoError(t, json.Unmarshal(raw, &bom))
	return raw, &bom
}

func writeCycloneDXBytes(t *testing.T, findings []Finding) []byte {
	t.Helper()
	var buffer bytes.Buffer
	require.NoError(t, NewCycloneDXReporter().Write(testWriter{&buffer}, findings))
	return append([]byte(nil), buffer.Bytes()...)
}

func requireCycloneDXComponent(t *testing.T, bom *CycloneDXBOM, name, version string) CycloneDXComponent {
	t.Helper()
	for _, component := range bom.Components {
		if component.Name == name && component.Version == version {
			return component
		}
	}
	t.Fatalf("component name=%q version=%q not found", name, version)
	return CycloneDXComponent{}
}

func hasCycloneDXProperty(properties []CycloneDXProperty, name, value string) bool {
	for _, property := range properties {
		if property.Name == name && property.Value == value {
			return true
		}
	}
	return false
}

func countCycloneDXProperties(properties []CycloneDXProperty, name string) int {
	count := 0
	for _, property := range properties {
		if property.Name == name {
			count++
		}
	}
	return count
}

func cycloneDXDependenciesByRef(bom *CycloneDXBOM) map[string][]string {
	dependencies := make(map[string][]string, len(bom.Dependencies))
	for _, dependency := range bom.Dependencies {
		dependencies[dependency.Ref] = dependency.DependsOn
	}
	return dependencies
}

func validateCycloneDXSchema(t *testing.T, raw []byte) {
	t.Helper()
	schema := compileCycloneDXSchema(t)
	var document any
	require.NoError(t, json.Unmarshal(raw, &document))
	if err := schema.Validate(document); err != nil {
		t.Fatalf("CycloneDX schema validation failed: %v", err)
	}
}

func compileCycloneDXSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	schemaDir := filepath.Join("..", "testdata", "cyclonedx", "1.5")
	files := map[string]string{
		"http://cyclonedx.org/schema/bom-1.5.schema.json":  "bom-1.5.schema.json",
		"http://cyclonedx.org/schema/spdx.schema.json":     "spdx.schema.json",
		"http://cyclonedx.org/schema/jsf-0.82.schema.json": "jsf-0.82.schema.json",
	}

	compiler := jsonschema.NewCompiler()
	for resourceURL, fileName := range files {
		file, err := os.Open(filepath.Join(schemaDir, fileName))
		require.NoError(t, err)
		document, err := jsonschema.UnmarshalJSON(file)
		require.NoError(t, err)
		require.NoError(t, file.Close())
		require.NoError(t, compiler.AddResource(resourceURL, document))
	}
	schema, err := compiler.Compile("http://cyclonedx.org/schema/bom-1.5.schema.json")
	require.NoError(t, err)
	return schema
}

type discardWriteCloser struct{}

func (d *discardWriteCloser) Write(p []byte) (int, error) {
	return io.Discard.Write(p)
}

func (d *discardWriteCloser) Close() error {
	return nil
}

type failOnWriteCloser struct {
	failAt int
	writes int
}

var errCycloneDXWriteFailure = errors.New("cyclonedx write failure")

func (w *failOnWriteCloser) Write(p []byte) (int, error) {
	w.writes++
	if w.writes >= w.failAt {
		return 0, errCycloneDXWriteFailure
	}
	return len(p), nil
}

func (w *failOnWriteCloser) Close() error {
	return nil
}

func TestEscapePURLSegment(t *testing.T) {
	tests := map[string]string{
		"MixedCase": "MixedCase",
		"a b":       "a%20b",
		"a/b":       "a%2Fb",
		"命名":        "%E5%91%BD%E5%90%8D",
	}
	for input, expected := range tests {
		t.Run(input, func(t *testing.T) {
			assert.Equal(t, expected, escapePURLSegment(input))
		})
	}
}

func BenchmarkCycloneDXReporterWrite(b *testing.B) {
	findings := benchmarkCycloneDXFindings(5000)
	reporter := NewCycloneDXReporter()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := reporter.Write(&discardWriteCloser{}, findings); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCycloneDXBufferedMarshal(b *testing.B) {
	findings := benchmarkCycloneDXFindings(5000)
	bom, err := BuildCycloneDXBOM(findings)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := json.Marshal(bom); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkCycloneDXFindings(count int) []Finding {
	findings := make([]Finding, count)
	for i := range findings {
		findings[i] = Finding{
			RuleID:    "rule-" + strconv.Itoa(i%100),
			Commit:    "commit-" + strconv.Itoa(i),
			File:      fmt.Sprintf("src/pkg%02d/file%04d.go", i%50, i),
			Secret:    fmt.Sprintf("secret-%d", i),
			StartLine: i + 1,
		}
	}
	return findings
}
