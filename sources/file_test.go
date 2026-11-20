package sources

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fatih/semgroup"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// collectFragments drains a source and returns the yielded fragments and
// any errors yielded alongside them (in order of appearance).
func collectFragments(t *testing.T, f *File) ([]Fragment, []error) {
	t.Helper()
	var (
		fragments []Fragment
		errs      []error
	)
	err := f.Fragments(context.Background(), func(fragment Fragment, err error) error {
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		fragments = append(fragments, fragment)
		return nil
	})
	require.NoError(t, err)
	return fragments, errs
}

// reassemble reconstructs the original stream from fragments by appending
// only the non-overlap part of each fragment.
func reassemble(fragments []Fragment) []byte {
	var out []byte
	for _, frag := range fragments {
		out = append(out, frag.Bytes[frag.OverlapBytes:]...)
	}
	return out
}

func TestFileFragments_ChunkBoundaryOverlap(t *testing.T) {
	// A secret straddling the read-buffer boundary must appear, whole, in
	// exactly one fragment's non-overlap region.
	secret := "AKIAIOSFODNN7EXAMPLE"
	content := strings.Repeat("a", 100) + secret + strings.Repeat("b", 100)

	f := &File{
		Content: strings.NewReader(content),
		Path:    "boundary.txt",
		Buffer:  make([]byte, 110), // secret starts at 100, buffer ends at 110
	}
	fragments, errs := collectFragments(t, f)
	require.Empty(t, errs)
	require.NotEmpty(t, fragments)

	// The stream must be reassemblable from the non-overlap parts.
	require.Equal(t, content, string(reassemble(fragments)))

	// Fragments must be anchored to cumulative byte offsets.
	var expectedOffset int64
	for _, frag := range fragments {
		require.True(t, frag.OffsetValid)
		require.Equal(t, expectedOffset, frag.Offset+int64(frag.OverlapBytes),
			"fragment new-data offset must be cumulative")
		expectedOffset += int64(len(frag.Bytes) - frag.OverlapBytes)
	}

	// The whole secret must be contained in at least one fragment.
	found := false
	for _, frag := range fragments {
		if strings.Contains(frag.Raw, secret) {
			found = true
		}
	}
	require.True(t, found, "secret split across chunk boundary was not recovered")

	// The overlap window must be bounded.
	for i, frag := range fragments {
		if i == 0 {
			require.Zero(t, frag.OverlapBytes)
		} else {
			require.LessOrEqual(t, frag.OverlapBytes, defaultMaxOverlapBytes)
		}
	}
}

func TestFileFragments_LongSingleLine(t *testing.T) {
	// No newlines at all: the safe-boundary peek is exhausted on every
	// chunk and the content is cut at arbitrary byte positions.
	secret := "AKIAIOSFODNN7EXAMPLE"
	content := strings.Repeat("x", 150_000) + secret + strings.Repeat("y", 150_000)

	f := &File{
		Content: strings.NewReader(content),
		Path:    "single-line.bin",
		Buffer:  make([]byte, 10_000),
	}
	fragments, errs := collectFragments(t, f)

	// The stream must be reassemblable and the secret recoverable.
	require.Equal(t, content, string(reassemble(fragments)))
	found := false
	for _, frag := range fragments {
		if strings.Contains(frag.Raw, secret) {
			found = true
		}
	}
	require.True(t, found)

	// The forced cuts must be marked as undecidable, not silently dropped.
	var truncations int
	for _, err := range errs {
		var te *TruncatedError
		require.ErrorAs(t, err, &te)
		require.Equal(t, "context-window-exceeded", te.Reason)
		truncations++
	}
	require.Equal(t, 1, truncations, "undecidable cut should be marked exactly once per stream")
}

func TestFileFragments_BinarySkipByDefault(t *testing.T) {
	// ELF magic + NUL bytes: classified application/x-executable.
	content := append([]byte("\x7fELF\x02\x01\x01\x00"), bytes.Repeat([]byte{0}, 64)...)
	content = append(content, []byte("AKIAIOSFODNN7EXAMPLE")...)

	f := &File{
		Content: bytes.NewReader(content),
		Path:    "firmware",
	}
	fragments, _ := collectFragments(t, f)
	require.Empty(t, fragments, "binary content must be skipped by default")
}

func TestFileFragments_ScanBinary(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	content := append([]byte("\x7fELF\x02\x01\x01\x00"), bytes.Repeat([]byte{0}, 64)...)
	content = append(content, []byte(secret)...)
	content = append(content, bytes.Repeat([]byte{0xff, 0x00}, 32)...)

	f := &File{
		Content:    bytes.NewReader(content),
		Path:       "firmware",
		ScanBinary: true,
	}
	fragments, errs := collectFragments(t, f)
	require.Empty(t, errs)
	require.NotEmpty(t, fragments)

	// Reassembly must reproduce the original byte stream (masking is
	// length-preserving)...
	require.Len(t, reassemble(fragments), len(content))

	// ...but fragments must never contain raw non-printable bytes.
	for _, frag := range fragments {
		require.True(t, frag.Binary)
		for _, r := range frag.Raw {
			require.True(t, r == '\n' || r == '\r' || r == '\t' || (r >= 0x20 && r <= 0x7e),
				"fragment contains non-printable rune %q", r)
		}
	}

	// The secret must be locatable by absolute byte offset.
	frag := fragments[0]
	idx := strings.Index(frag.Raw, secret)
	require.GreaterOrEqual(t, idx, 0)
	absOffset := frag.Offset + int64(idx)
	require.Equal(t, secret, string(content[absOffset:absOffset+int64(len(secret))]))
}

func TestFileFragments_ReadErrorPartialResult(t *testing.T) {
	// The reader yields one good chunk and then fails.
	r := &failAfterReader{
		data: []byte(strings.Repeat("a\n", 100) + "AKIAIOSFODNN7EXAMPLE\n"),
		err:  errors.New("disk on fire"),
	}
	f := &File{
		Content: r,
		Path:    "flaky.txt",
		Buffer:  make([]byte, 50),
	}
	fragments, errs := collectFragments(t, f)

	require.NotEmpty(t, fragments, "confirmed fragments before the error must be returned")
	var truncErr *TruncatedError
	require.NotEmpty(t, errs)
	require.ErrorAs(t, errs[len(errs)-1], &truncErr)
	require.Equal(t, "read-error", truncErr.Reason)
	require.Equal(t, "flaky.txt", truncErr.Path)
}

type failAfterReader struct {
	data []byte
	err  error
}

func (r *failAfterReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestFileFragments_UTF8Boundary(t *testing.T) {
	// Force a chunk boundary into the middle of a multi-byte character:
	// with no newlines the peek limit is exhausted and the chunk is cut
	// at exactly bufferSize+maxPeekSize bytes, inside the second char.
	prefix := strings.Repeat("a", 25_098)
	multibyte := "世界" // 3 bytes each, spans the cut at 25_100
	suffix := strings.Repeat("b", 100)
	content := prefix + multibyte + suffix

	f := &File{
		Content: strings.NewReader(content),
		Path:    "utf8.txt",
		Buffer:  make([]byte, 100),
	}
	fragments, errs := collectFragments(t, f)
	require.Equal(t, content, string(reassemble(fragments)))

	// The multibyte sequence must appear whole in at least one fragment.
	found := false
	for _, frag := range fragments {
		if strings.Contains(frag.Raw, multibyte) {
			found = true
		}
	}
	require.True(t, found, "multi-byte character split at chunk boundary was not recovered")

	// The forced cut is marked undecidable exactly once.
	var truncations int
	for _, err := range errs {
		var te *TruncatedError
		require.ErrorAs(t, err, &te)
		truncations++
	}
	require.Equal(t, 1, truncations)
}

func TestFileFragments_ArchiveMemberLimit(t *testing.T) {
	// tar with one huge member and one small member: the huge member is
	// truncated and marked, the small member is still scanned.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	big := bytes.Repeat([]byte("A"), 10_000)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "big.bin", Mode: 0o600, Size: int64(len(big))}))
	_, err := tw.Write(big)
	require.NoError(t, err)

	small := []byte("AKIAIOSFODNN7EXAMPLE")
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "small.txt", Mode: 0o600, Size: int64(len(small))}))
	_, err = tw.Write(small)
	require.NoError(t, err)
	require.NoError(t, tw.Close())

	f := &File{
		Content:         bytes.NewReader(buf.Bytes()),
		Path:            "test.tar",
		MaxArchiveDepth: 1,
		ArchiveLimits: ArchiveLimits{
			MaxMemberBytes: 5_000,
		},
	}
	fragments, errs := collectFragments(t, f)

	// The small member is still scanned.
	var paths []string
	for _, frag := range fragments {
		paths = append(paths, frag.FilePath)
	}
	require.Contains(t, paths, "test.tar!small.txt")

	// The oversized member produced a truncation marker.
	var truncErr *TruncatedError
	foundTruncation := false
	for _, err := range errs {
		if errors.As(err, &truncErr) && truncErr.Reason == "archive-member-limit" {
			foundTruncation = true
			require.Equal(t, "test.tar!big.bin", truncErr.Path)
		}
	}
	require.True(t, foundTruncation, "oversized member must be marked truncated")
}

func TestFileFragments_ArchiveMaxMembers(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := 0; i < 5; i++ {
		data := []byte(fmt.Sprintf("content-%d", i))
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("f%d.txt", i), Mode: 0o600, Size: int64(len(data))}))
		_, err := tw.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())

	f := &File{
		Content:         bytes.NewReader(buf.Bytes()),
		Path:            "test.tar",
		MaxArchiveDepth: 1,
		ArchiveLimits:   ArchiveLimits{MaxMembers: 2},
	}
	fragments, _ := collectFragments(t, f)
	require.LessOrEqual(t, len(fragments), 2, "member limit must stop the archive branch")
}

func TestFileFragments_ArchiveSpillQuota(t *testing.T) {
	// A zip read from a non-seekable stream must be spilled to disk, but
	// the spill is quota-bound and the temp file is cleaned up.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("secret.txt")
	require.NoError(t, err)
	_, err = w.Write([]byte("AKIAIOSFODNN7EXAMPLE"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	tmp := os.TempDir()
	countSpill := func() int {
		matches, _ := filepath.Glob(filepath.Join(tmp, "gitleaks-archive-*"))
		return len(matches)
	}
	before := countSpill()

	f := &File{
		Content:         &noSeekReader{r: bytes.NewReader(buf.Bytes())},
		Path:            "test.zip",
		MaxArchiveDepth: 1,
		ArchiveLimits:   ArchiveLimits{MaxSpillBytes: 10}, // way below the zip size
	}
	_, errs := collectFragments(t, f)

	var truncErr *TruncatedError
	found := false
	for _, err := range errs {
		if errors.As(err, &truncErr) && truncErr.Reason == "archive-spill-limit" {
			found = true
		}
	}
	require.True(t, found, "spill quota overflow must be marked")
	require.Equal(t, before, countSpill(), "temporary spill files must be cleaned up")
}

// noSeekReader hides the Seek method of the wrapped reader.
type noSeekReader struct{ r io.Reader }

func (n *noSeekReader) Read(p []byte) (int, error) { return n.r.Read(p) }

func TestFileFragments_StdinLikeStream(t *testing.T) {
	// A non-seekable stream (like stdin) must be scanned without
	// re-reading or spilling to disk.
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write([]byte(strings.Repeat("line\n", 1000)))
		_ = pw.Close()
	}()

	f := &File{
		Content: pr,
		Path:    "",
		Buffer:  make([]byte, 128),
	}
	fragments, errs := collectFragments(t, f)
	require.Empty(t, errs)
	require.Equal(t, strings.Repeat("line\n", 1000), string(reassemble(fragments)))
}

func TestByteBudget(t *testing.T) {
	budget := NewByteBudget(100)
	require.NotNil(t, budget)
	require.Equal(t, int64(100), budget.Max())

	// Nil budget is a no-op.
	var nilBudget *ByteBudget
	release := nilBudget.Acquire(context.Background(), 1_000_000)
	release()

	ctx := context.Background()
	r1 := budget.Acquire(ctx, 60)

	// A request exceeding available budget blocks until budget is released.
	acquired := make(chan func(), 1)
	go func() {
		acquired <- budget.Acquire(ctx, 50)
	}()
	select {
	case <-acquired:
		t.Fatal("acquire should block while budget is exhausted")
	default:
	}
	r1()
	r2 := <-acquired
	r2()

	// A request larger than the whole budget is clamped, not deadlocked.
	r3 := budget.Acquire(ctx, 1_000_000)
	r3()

	// Concurrent holders never exceed the budget.
	var (
		wg      sync.WaitGroup
		maxSeen int64
		mu      sync.Mutex
		current int64
	)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release := budget.Acquire(ctx, 10)
			mu.Lock()
			current += 10
			if current > maxSeen {
				maxSeen = current
			}
			mu.Unlock()
			release()
			mu.Lock()
			current -= 10
			mu.Unlock()
		}()
	}
	wg.Wait()
	require.LessOrEqual(t, maxSeen, int64(100))
}

func TestIsTruncated(t *testing.T) {
	require.False(t, IsTruncated(errors.New("boom")))
	require.True(t, IsTruncated(&TruncatedError{Reason: "read-error"}))
	require.True(t, IsTruncated(fmt.Errorf("wrap: %w", &TruncatedError{Reason: "x"})))
}

func TestFileFragments_ContextCancellation(t *testing.T) {
	// An infinite stream must be abandoned promptly when the context is
	// canceled.
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	go func() {
		for i := 0; ; i++ {
			if _, err := pw.Write([]byte("some data\n")); err != nil {
				return
			}
		}
	}()
	defer pw.Close()

	var fragments int
	done := make(chan error, 1)
	f := &File{Content: pr, Path: "endless.log"}
	go func() {
		done <- f.Fragments(ctx, func(fragment Fragment, err error) error {
			if err != nil {
				return nil
			}
			fragments++
			if fragments == 3 {
				cancel()
			}
			return nil
		})
	}()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("scan did not stop after context cancellation")
	}
}

func TestFileFragments_MalformedArchive(t *testing.T) {
	// A corrupt archive must not crash the scan; the branch fails and
	// other files are unaffected.
	corrupt := []byte("PK\x03\x04" + strings.Repeat("garbage", 100))
	f := &File{
		Content:         bytes.NewReader(corrupt),
		Path:            "corrupt.zip",
		MaxArchiveDepth: 1,
	}
	// Must not panic; an error (or a clean skip) is acceptable.
	_ = f.Fragments(context.Background(), func(fragment Fragment, err error) error {
		return nil
	})

	// A directory scan continues past the corrupt archive.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "corrupt.zip"), corrupt, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "good.txt"), []byte("hello world"), 0o600))

	files := &Files{Path: dir, Sema: newTestSema(), MaxArchiveDepth: 1}
	var paths []string
	err := files.Fragments(context.Background(), func(fragment Fragment, err error) error {
		if err == nil {
			paths = append(paths, fragment.FilePath)
		}
		return nil
	})
	require.NoError(t, err)
	require.Contains(t, paths, filepath.Join(dir, "good.txt"))
}

func newTestSema() *semgroup.Group {
	return semgroup.NewGroup(context.Background(), 4)
}

func TestMaskNonPrintable(t *testing.T) {
	in := []byte("ab\x00cd\x7f\xff\n\t~")
	maskNonPrintable(in)
	require.Equal(t, "ab.cd..\n\t~", string(in))
	require.True(t, looksBinary([]byte("a\x00b")))
	assert.False(t, looksBinary([]byte("plain text")))
}
