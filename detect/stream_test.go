package detect

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// streamTestSecret is a 20-byte AWS-like token used across the streaming
// tests.
const streamTestSecret = "AKIAIOSFODNN7EXAMPLE"

// newStreamTestDetector builds a detector with a single AWS-like rule.
func newStreamTestDetector(t *testing.T) *Detector {
	t.Helper()
	rule := config.Rule{
		RuleID:   "stream-test-aws",
		Regex:    regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Keywords: []string{"akia"},
	}
	cfg := config.Config{
		Rules:    map[string]config.Rule{rule.RuleID: rule},
		Keywords: map[string]struct{}{"akia": {}},
	}
	return NewDetector(cfg)
}

// scanContent scans content with the given buffer size and returns the
// findings.
func scanContent(t *testing.T, d *Detector, content io.Reader, bufSize int) []report.Finding {
	t.Helper()
	_, err := d.DetectSource(context.Background(), &sources.File{
		Content: content,
		Path:    "stream-test.txt",
		Buffer:  make([]byte, bufSize),
	})
	require.NoError(t, err)
	return d.Findings()
}

// TestDetectStream_ChunkBoundary verifies that a secret straddling a
// forced chunk cut is detected exactly once, at the hand-computed byte
// offset, line and column.
func TestDetectStream_ChunkBoundary(t *testing.T) {
	const (
		bufSize   = 100
		chunkSize = bufSize + 25_000 // buffer + maxPeekSize, no safe boundary in padding
	)
	// Place the secret so it straddles the first forced cut.
	secretOffset := chunkSize - 10
	content := strings.Repeat("a", secretOffset) + streamTestSecret + strings.Repeat("b", 30_000)

	d := newStreamTestDetector(t)
	findings := scanContent(t, d, strings.NewReader(content), bufSize)

	require.Len(t, findings, 1, "boundary secret must be reported exactly once")
	f := findings[0]
	assert.Equal(t, int64(secretOffset), f.StartOffset)
	assert.Equal(t, int64(secretOffset+len(streamTestSecret)), f.EndOffset)
	assert.Equal(t, 1, f.StartLine)
	assert.Equal(t, secretOffset+1, f.StartColumn)
	assert.Equal(t, streamTestSecret, f.Secret)
	// The fingerprint must agree with the reported position.
	assert.Equal(t, fmt.Sprintf("stream-test.txt:stream-test-aws:%d", f.StartLine), f.Fingerprint)
}

// TestDetectStream_LongSingleLine verifies offsets inside a huge
// newline-free file.
func TestDetectStream_LongSingleLine(t *testing.T) {
	secretOffset := 150_000
	content := strings.Repeat("x", secretOffset) + streamTestSecret + strings.Repeat("y", 150_000)

	d := newStreamTestDetector(t)
	findings := scanContent(t, d, strings.NewReader(content), 100_000)

	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, int64(secretOffset), f.StartOffset)
	assert.Equal(t, int64(secretOffset+len(streamTestSecret)), f.EndOffset)
	assert.Equal(t, 1, f.StartLine)
	assert.Equal(t, secretOffset+1, f.StartColumn)

	// The forced cuts along the way must be marked as undecidable.
	assert.GreaterOrEqual(t, d.Truncations(), int64(1))
}

// TestDetectStream_MultiChunkSecret verifies that a secret spanning
// multiple chunks is recovered when the context window is configured
// large enough.
func TestDetectStream_MultiChunkSecret(t *testing.T) {
	// A 30kb secret spans at least two 25.1kb chunks.
	longSecret := "AKIA" + strings.Repeat("Z", 30_000)
	rule := config.Rule{
		RuleID:   "stream-test-long",
		Regex:    regexp.MustCompile(`AKIAZ+`),
		Keywords: []string{"akia"},
	}
	cfg := config.Config{
		Rules:    map[string]config.Rule{rule.RuleID: rule},
		Keywords: map[string]struct{}{"akia": {}},
	}
	d := NewDetector(cfg)

	const secretOffset = 25_095 // straddles the first forced cut
	content := strings.Repeat("a", secretOffset) + longSecret + strings.Repeat("b", 10_000)

	_, err := d.DetectSource(context.Background(), &sources.File{
		Content:         strings.NewReader(content),
		Path:            "multi-chunk.txt",
		Buffer:          make([]byte, 100),
		MaxOverlapBytes: 64_000, // window must cover the oversized secret
	})
	require.NoError(t, err)

	findings := d.Findings()
	require.Len(t, findings, 1, "multi-chunk secret must be reported exactly once")
	assert.Equal(t, int64(secretOffset), findings[0].StartOffset)
	assert.Equal(t, int64(secretOffset+len(longSecret)), findings[0].EndOffset)
}

// TestDetectStream_OverlapDedup verifies that occurrences visible through
// the overlap window are reported once, at the earliest position, while
// distinct occurrences are all reported.
func TestDetectStream_OverlapDedup(t *testing.T) {
	const (
		bufSize   = 100
		chunkSize = bufSize + 25_000
	)
	var b strings.Builder
	b.WriteString(strings.Repeat("a", 100))
	first := 100
	b.WriteString(streamTestSecret)
	b.WriteString(strings.Repeat("c", 40_000))
	second := 100 + len(streamTestSecret) + 40_000
	b.WriteString(streamTestSecret)
	b.WriteString(strings.Repeat("d", 40_000))
	content := b.String()

	d := newStreamTestDetector(t)
	findings := scanContent(t, d, strings.NewReader(content), bufSize)

	require.Len(t, findings, 2, "each distinct occurrence must be reported exactly once")
	offsets := []int64{findings[0].StartOffset, findings[1].StartOffset}
	assert.Contains(t, offsets, int64(first))
	assert.Contains(t, offsets, int64(second))
	_ = chunkSize
}

// TestDetectStream_Binary verifies byte-range localization in binary
// content and that the report stays free of raw binary.
func TestDetectStream_Binary(t *testing.T) {
	var content []byte
	content = append(content, 0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00)
	content = append(content, bytes.Repeat([]byte{0x00, 0xff, 0x01}, 100)...)
	secretOffset := int64(len(content))
	content = append(content, streamTestSecret...)
	content = append(content, bytes.Repeat([]byte{0x00}, 100)...)

	// Default behavior is unchanged: binary content is skipped.
	d := newStreamTestDetector(t)
	_, err := d.DetectSource(context.Background(), &sources.File{
		Content: bytes.NewReader(content),
		Path:    "firmware",
	})
	require.NoError(t, err)
	require.Empty(t, d.Findings())

	// With ScanBinary, the secret is located by byte range.
	d = newStreamTestDetector(t)
	d.ScanBinary = true
	_, err = d.DetectSource(context.Background(), &sources.File{
		Content:    bytes.NewReader(content),
		Path:       "firmware",
		ScanBinary: d.ScanBinary,
	})
	require.NoError(t, err)
	findings := d.Findings()
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, secretOffset, f.StartOffset)
	assert.Equal(t, secretOffset+int64(len(streamTestSecret)), f.EndOffset)
	// The byte range maps back to the original image.
	assert.Equal(t, streamTestSecret, string(content[f.StartOffset:f.EndOffset]))
	// The reported line must not contain raw binary.
	for _, r := range f.Line {
		assert.True(t, r == '\n' || r == '\r' || r == '\t' || (r >= 0x20 && r <= 0x7e),
			"line contains non-printable rune %q", r)
	}
}

// TestDetectStream_LargeFileMemoryBound builds a large file from repeated
// content and verifies that resident memory stays far below the file
// size while every secret is found.
func TestDetectStream_LargeFileMemoryBound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large-file memory test in short mode")
	}

	// ~64MB of repeated content with 64 secrets at known spacing.
	const secrets = 64
	chunk := strings.Repeat("padding\n", 1000) + "token=" + streamTestSecret + "\n"
	var estimated int64
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.log")
	f, err := os.Create(path)
	require.NoError(t, err)
	for i := 0; i < secrets; i++ {
		_, err = f.WriteString(chunk)
		require.NoError(t, err)
		// 1MB of filler between secrets
		_, err = f.WriteString(strings.Repeat("filler\n", 150_000))
		require.NoError(t, err)
		estimated += int64(len(chunk)) + 1_050_000
	}
	require.NoError(t, f.Close())
	info, err := os.Stat(path)
	require.NoError(t, err)
	t.Logf("file size: %d bytes", info.Size())

	d := newStreamTestDetector(t)
	d.MemoryBudget = sources.NewByteBudget(4_000_000) // 4MB shared budget

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	_, err = d.DetectSource(context.Background(), &sources.Files{
		Path:   dir,
		Sema:   d.Sema,
		Budget: d.MemoryBudget,
	})
	require.NoError(t, err)

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	require.Len(t, d.Findings(), secrets)
	// Resident heap growth must stay far below the file size: the file is
	// streamed, not held.
	growth := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("heap growth: %d bytes", growth)
	assert.Less(t, growth, info.Size()/4,
		"heap growth must not scale with file size")
	assert.Less(t, growth, int64(64_000_000))
}

// TestDetectStream_SharedBudgetConcurrency verifies that multiple large
// files scanned in parallel complete under a shared memory budget.
func TestDetectStream_SharedBudgetConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping concurrency budget test in short mode")
	}

	dir := t.TempDir()
	const files = 4
	for i := 0; i < files; i++ {
		// Small blocks with blank-line separators so chunk boundaries
		// always land on safe split points.
		unit := strings.Repeat("x", 1000) + "\n\n"
		var b strings.Builder
		for j := 0; j < 200; j++ {
			b.WriteString(unit)
			if j%40 == 10 {
				b.WriteString("token=" + streamTestSecret + "\n\n")
			}
		}
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("big-%d.log", i)),
			[]byte(b.String()), 0o600,
		))
	}

	d := newStreamTestDetector(t)
	// Budget for roughly two concurrent scans: forces sharing without
	// deadlocking.
	d.MemoryBudget = sources.NewByteBudget(600_000)

	_, err := d.DetectSource(context.Background(), &sources.Files{
		Path:   dir,
		Sema:   d.Sema,
		Budget: d.MemoryBudget,
	})
	require.NoError(t, err)
	assert.Len(t, d.Findings(), files*5)
	assert.Zero(t, d.Truncations())
}

// TestDetectStream_ReadError verifies that a mid-stream I/O error yields
// the confirmed findings and marks the result incomplete.
func TestDetectStream_ReadError(t *testing.T) {
	r := &streamFailReader{
		data: []byte("token=" + streamTestSecret + "\n" + strings.Repeat("a\n", 100)),
		err:  errors.New("io error"),
	}
	d := newStreamTestDetector(t)
	_, err := d.DetectSource(context.Background(), &sources.File{
		Content: r,
		Path:    "flaky.txt",
		Buffer:  make([]byte, 32),
	})
	require.NoError(t, err)

	require.Len(t, d.Findings(), 1, "confirmed findings before the error must be kept")
	assert.Equal(t, streamTestSecret, d.Findings()[0].Secret)
	assert.Equal(t, int64(1), d.Truncations(), "partial result must be marked")
}

type streamFailReader struct {
	data []byte
	err  error
}

func (r *streamFailReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// TestDetectStream_Stdin verifies scanning a non-seekable stream (like
// stdin) without buffering to disk.
func TestDetectStream_Stdin(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		for i := 0; i < 500; i++ {
			fmt.Fprintf(pw, "line %d\n", i)
		}
		fmt.Fprintf(pw, "token=%s\n", streamTestSecret)
	}()

	d := newStreamTestDetector(t)
	_, err := d.DetectSource(context.Background(), &sources.File{Content: pr})
	require.NoError(t, err)
	require.Len(t, d.Findings(), 1)
	assert.Equal(t, 501, d.Findings()[0].StartLine)
}

// TestDetectStream_NestedArchiveLimits verifies that hitting an expansion
// limit inside a nested archive only stops that branch.
func TestDetectStream_NestedArchiveLimits(t *testing.T) {
	// inner.tar: one huge member, one member with a secret.
	inner := buildTar(t, map[string][]byte{
		"huge.bin":   bytes.Repeat([]byte("H"), 200_000),
		"secret.txt": []byte("token=" + streamTestSecret),
	})
	// outer.tar: the nested archive plus a top-level secret.
	outer := buildTar(t, map[string][]byte{
		"inner.tar": inner,
		"top.txt":   []byte("token=" + streamTestSecret),
	})

	dir := t.TempDir()
	path := filepath.Join(dir, "outer.tar")
	require.NoError(t, os.WriteFile(path, outer, 0o600))

	d := newStreamTestDetector(t)
	_, err := d.DetectSource(context.Background(), &sources.File{
		Content:         mustOpen(t, path),
		Path:            path,
		MaxArchiveDepth: 2,
		ArchiveLimits: sources.ArchiveLimits{
			MaxMemberBytes: 100_000,
		},
	})
	require.NoError(t, err)

	// Both the top-level secret and the nested small member are found;
	// only the oversized member is cut.
	var files []string
	for _, f := range d.Findings() {
		files = append(files, f.File)
	}
	assert.Contains(t, files, path+"!top.txt")
	assert.Contains(t, files, path+"!inner.tar!secret.txt")
	assert.GreaterOrEqual(t, d.Truncations(), int64(1), "oversized member must be marked")

	// Temp spill files, if any, are cleaned up.
	matches, _ := filepath.Glob(filepath.Join(os.TempDir(), "gitleaks-archive-*"))
	assert.Empty(t, matches)
}

// TestDetectStream_BaselineConsistency verifies that offsets, fingerprints
// and baseline suppression all derive from the same position data.
func TestDetectStream_BaselineConsistency(t *testing.T) {
	dir := t.TempDir()
	content := strings.Repeat("a\n", 500) + "token=" + streamTestSecret + "\n" + strings.Repeat("b\n", 500)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.log"), []byte(content), 0o600))

	scan := func() *Detector {
		d := newStreamTestDetector(t)
		_, err := d.DetectSource(context.Background(), &sources.Files{
			Path: dir,
			Sema: d.Sema,
		})
		require.NoError(t, err)
		return d
	}

	first := scan()
	require.Len(t, first.Findings(), 1)
	f := first.Findings()[0]
	require.Equal(t, fmt.Sprintf("%s:stream-test-aws:%d", filepath.Join(dir, "app.log"), f.StartLine), f.Fingerprint)
	require.NotZero(t, f.EndOffset)

	// Write a baseline report (outside the scanned directory) and confirm
	// the finding is suppressed on the next run.
	baselineDir := t.TempDir()
	baselinePath := filepath.Join(baselineDir, "baseline.json")
	w, err := os.Create(baselinePath)
	require.NoError(t, err)
	require.NoError(t, (&report.JsonReporter{}).Write(w, first.Findings()))
	require.NoError(t, w.Close())

	second := newStreamTestDetector(t)
	require.NoError(t, second.AddBaseline(baselinePath, dir))
	_, err = second.DetectSource(context.Background(), &sources.Files{
		Path: dir,
		Sema: second.Sema,
	})
	require.NoError(t, err)
	assert.Empty(t, second.Findings(), "baseline suppression must keep working")
}

func buildTar(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, data := range members {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o600,
			Size: int64(len(data)),
		}))
		_, err := tw.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	return buf.Bytes()
}

func mustOpen(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	return f
}
