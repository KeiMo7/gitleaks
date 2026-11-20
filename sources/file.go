package sources

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/h2non/filetype"
	"github.com/mholt/archives"
	"github.com/rs/zerolog"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
)

const defaultBufferSize = 100 * 1_000 // 100kb

// defaultMaxOverlapBytes bounds the cross-chunk context window that is
// carried from one fragment into the next so secrets split across read
// boundaries are still detected. 16kb covers every realistic secret
// (PEM blocks, JWTs, connection strings) while keeping per-file memory
// and re-scan overhead small.
const defaultMaxOverlapBytes = 16 * 1_000 // 16kb

const InnerPathSeparator = "!"

// errArchiveLimit is a sentinel used to abort extraction of a single
// archive when one of its limits is exceeded. It is never returned to
// callers; hitting it only stops the offending branch.
var errArchiveLimit = errors.New("archive limit exceeded")

type seekReaderAt interface {
	io.ReaderAt
	io.Seeker
}

// ArchiveLimits bounds how much work archive extraction may do for a
// single archive. The zero value means "unlimited" for every dimension,
// which preserves the historical default behavior. When a limit is hit,
// only the offending archive (branch) is stopped; a TruncatedError is
// yielded so the result is marked incomplete instead of silently empty.
type ArchiveLimits struct {
	// MaxMembers limits how many members are extracted per archive.
	MaxMembers int
	// MaxMemberBytes limits the expanded size of a single member.
	MaxMemberBytes int64
	// MaxTotalBytes limits the expanded size of all members of one
	// archive combined (decompression-bomb guard).
	MaxTotalBytes int64
	// MaxSpillBytes limits how many bytes may be written to a temporary
	// file when an archive must be spilled to disk (zip/7z read from a
	// non-seekable stream, e.g. stdin).
	MaxSpillBytes int64
}

// File is a source for yielding fragments from a file or other reader
type File struct {
	// Content provides a reader to the file's content
	Content io.Reader
	// Path is the resolved real path of the file
	Path string
	// Symlink represents a symlink to the file if that's how it was discovered
	Symlink string
	// Buffer is used for reading the content in chunks
	Buffer []byte
	// Config is the gitleaks config used for shouldSkipPath. If not set, then
	// shouldSkipPath is ignored
	Config *config.Config
	// outerPaths is the list of container paths (e.g. archives) that lead to
	// this file
	outerPaths []string
	// MaxArchiveDepth limits how deep the sources will explore nested archives
	MaxArchiveDepth int
	// archiveDepth is the current archive nesting depth
	archiveDepth int

	// ScanBinary enables scanning of content detected as binary
	// (application/* MIME types or NUL-containing data) instead of
	// skipping it. Non-printable bytes are masked with '.' before
	// scanning; positions remain byte-accurate. The default (false)
	// preserves the historical skip behavior.
	ScanBinary bool

	// MaxOverlapBytes bounds the cross-chunk context window carried
	// between fragments. Zero uses defaultMaxOverlapBytes.
	MaxOverlapBytes int

	// Budget, when set, bounds the total buffer memory this scan may
	// hold; it is shared across concurrent scans.
	Budget *ByteBudget

	// ArchiveLimits bounds archive extraction work. Zero means unlimited.
	ArchiveLimits ArchiveLimits
}

// Fragments yields fragments for the this source
func (s *File) Fragments(ctx context.Context, yield FragmentsFunc) error {
	format, _, err := archives.Identify(ctx, s.Path, nil)
	// Process the file as an archive if there's no error && Identify returns
	// a format; but if there's an error or no format, just swallow the error
	// and fall back on treating it like a normal file and let fileFragments
	// decide what to do with it.
	if err == nil && format != nil {
		if s.archiveDepth+1 > s.MaxArchiveDepth {
			var event *zerolog.Event

			// Warn if the feature is enabled; else emit a trace log.
			if s.MaxArchiveDepth != 0 {
				event = logging.Warn()
			} else {
				event = logging.Trace()
			}

			event.Str(
				"path", s.FullPath(),
			).Int(
				"max_archive_depth", s.MaxArchiveDepth,
			).Msg("skipping archive: exceeds max archive depth")

			return nil
		}
		if extractor, ok := format.(archives.Extractor); ok {
			return s.extractorFragments(ctx, extractor, s.Content, yield)
		}
		if decompressor, ok := format.(archives.Decompressor); ok {
			return s.decompressorFragments(ctx, decompressor, s.Content, yield)
		}
		logging.Warn().Str("path", s.FullPath()).Msg("skipping unknown archive type")
	}

	return s.fileFragments(ctx, bufio.NewReader(s.Content), yield)
}

// limitedReader wraps a reader and records how many bytes were consumed,
// so callers can enforce expanded-size limits on archive members.
type limitedReader struct {
	r io.Reader
	n int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.n += int64(n)
	return n, err
}

// extractorFragments recursively crawls archives and yields fragments
func (s *File) extractorFragments(ctx context.Context, extractor archives.Extractor, reader io.Reader, yield FragmentsFunc) error {
	if _, isSeekReaderAt := reader.(seekReaderAt); !isSeekReaderAt {
		switch extractor.(type) {
		case archives.SevenZip, archives.Zip:
			tmpfile, err := os.CreateTemp("", "gitleaks-archive-")
			if err != nil {
				logging.Error().Str("path", s.FullPath()).Msg("could not create tmp file")
				return nil
			}
			// The temporary spill file is always removed, including on
			// failure and context cancellation.
			defer func() {
				_ = tmpfile.Close()
				_ = os.Remove(tmpfile.Name())
			}()

			spillLimit := s.ArchiveLimits.MaxSpillBytes
			if spillLimit > 0 {
				// Copy at most spillLimit+1 bytes so we can detect the
				// overflow without writing unbounded data to disk.
				written, copyErr := io.CopyN(tmpfile, reader, spillLimit+1)
				if copyErr != nil && copyErr != io.EOF {
					logging.Error().Str("path", s.FullPath()).Msg("could not copy archive file")
					return nil
				}
				if written > spillLimit {
					logging.Warn().Str("path", s.FullPath()).Int64("max_spill_bytes", spillLimit).
						Msg("skipping archive: exceeds temp spill quota")
					return yield(Fragment{FilePath: s.FullPath()}, &TruncatedError{
						Path:   s.FullPath(),
						Reason: "archive-spill-limit",
					})
				}
			} else {
				_, err = io.Copy(tmpfile, reader)
				if err != nil {
					logging.Error().Str("path", s.FullPath()).Msg("could not copy archive file")
					return nil
				}
			}

			reader = tmpfile
		}
	}

	var (
		memberCount int
		totalBytes  int64
	)

	err := extractor.Extract(ctx, reader, func(_ context.Context, d archives.FileInfo) error {
		if d.IsDir() {
			return nil
		}

		memberCount++
		if s.ArchiveLimits.MaxMembers > 0 && memberCount > s.ArchiveLimits.MaxMembers {
			logging.Warn().Str("path", s.FullPath()).Int("max_members", s.ArchiveLimits.MaxMembers).
				Msg("stopping archive extraction: exceeds max members")
			return errArchiveLimit
		}

		innerReader, err := d.Open()
		if err != nil {
			logging.Error().Err(err).Str("path", s.FullPath()).Msg("could not open archive inner file")
			return nil
		}
		defer innerReader.Close()
		path := filepath.Clean(d.NameInArchive)

		if s.Config != nil && shouldSkipPath(s.Config, path) {
			logging.Debug().Str("path", s.FullPath()).Msg("skipping file: global allowlist")
			return nil
		}

		// Bound the expanded size of each member and of the archive as a
		// whole. The limit reader allows one byte past the cap so the
		// overflow is detectable.
		var content io.Reader = innerReader
		lr := &limitedReader{r: innerReader}
		if s.ArchiveLimits.MaxMemberBytes > 0 || s.ArchiveLimits.MaxTotalBytes > 0 {
			content = lr
		}

		file := &File{
			Content:         content,
			Path:            path,
			Symlink:         s.Symlink,
			outerPaths:      append(s.outerPaths, filepath.ToSlash(s.Path)),
			MaxArchiveDepth: s.MaxArchiveDepth,
			archiveDepth:    s.archiveDepth + 1,
			ScanBinary:      s.ScanBinary,
			MaxOverlapBytes: s.MaxOverlapBytes,
			Budget:          s.Budget,
			ArchiveLimits:   s.ArchiveLimits,
		}

		fragErr := file.Fragments(ctx, yield)

		if lr.n > 0 {
			totalBytes += lr.n
			memberPath := file.FullPath()
			if s.ArchiveLimits.MaxMemberBytes > 0 && lr.n > s.ArchiveLimits.MaxMemberBytes {
				logging.Warn().Str("path", memberPath).Int64("max_member_bytes", s.ArchiveLimits.MaxMemberBytes).
					Msg("archive member truncated: exceeds max member size")
				if yerr := yield(Fragment{FilePath: memberPath}, &TruncatedError{
					Path:   memberPath,
					Offset: s.ArchiveLimits.MaxMemberBytes,
					Reason: "archive-member-limit",
				}); yerr != nil {
					return yerr
				}
			}
			if s.ArchiveLimits.MaxTotalBytes > 0 && totalBytes > s.ArchiveLimits.MaxTotalBytes {
				logging.Warn().Str("path", s.FullPath()).Int64("max_total_bytes", s.ArchiveLimits.MaxTotalBytes).
					Msg("stopping archive extraction: exceeds max total expanded size")
				if yerr := yield(Fragment{FilePath: s.FullPath()}, &TruncatedError{
					Path:   s.FullPath(),
					Reason: "archive-total-limit",
				}); yerr != nil {
					return yerr
				}
				return errArchiveLimit
			}
		}

		return fragErr
	})

	if errors.Is(err, errArchiveLimit) {
		// Only this archive branch was stopped; the scan continues.
		return nil
	}
	return err
}

// decompressorFragments recursively crawls archives and yields fragments
func (s *File) decompressorFragments(ctx context.Context, decompressor archives.Decompressor, reader io.Reader, yield FragmentsFunc) error {
	innerReader, err := decompressor.OpenReader(reader)
	if err != nil {
		logging.Error().Str("path", s.FullPath()).Msg("could read compressed file")
		return nil
	}

	// Bound the expanded size of the decompressed stream.
	var content io.Reader = innerReader
	lr := &limitedReader{r: innerReader}
	if s.ArchiveLimits.MaxMemberBytes > 0 {
		content = lr
	}

	fragErr := s.fileFragments(ctx, bufio.NewReader(content), yield)
	_ = innerReader.Close()

	if s.ArchiveLimits.MaxMemberBytes > 0 && lr.n > s.ArchiveLimits.MaxMemberBytes {
		logging.Warn().Str("path", s.FullPath()).Int64("max_member_bytes", s.ArchiveLimits.MaxMemberBytes).
			Msg("decompressed stream truncated: exceeds max member size")
		if yerr := yield(Fragment{FilePath: s.FullPath()}, &TruncatedError{
			Path:   s.FullPath(),
			Offset: s.ArchiveLimits.MaxMemberBytes,
			Reason: "archive-member-limit",
		}); yerr != nil {
			return yerr
		}
	}

	return fragErr
}

// fileFragments reads the file into fragments to yield.
//
// The reader is consumed in bounded chunks; a bounded overlap window (the
// tail of the previous chunk) is prepended to each fragment so that
// secrets straddling chunk boundaries are still detected. Positions are
// tracked as cumulative byte offsets, so every fragment can be mapped
// back to an exact byte range of the original stream, and resident
// memory stays constant regardless of the total stream size.
func (s *File) fileFragments(ctx context.Context, reader *bufio.Reader, yield FragmentsFunc) error {
	// Create a buffer if the caller hasn't provided one
	if s.Buffer == nil {
		s.Buffer = make([]byte, defaultBufferSize)
	}

	maxOverlap := s.MaxOverlapBytes
	if maxOverlap <= 0 {
		maxOverlap = defaultMaxOverlapBytes
	}

	// Acquire our share of the shared memory budget: read buffer + peek
	// headroom + the overlap carry window. Total memory across all
	// concurrent scans stays under the budget ceiling.
	if s.Budget != nil {
		release := s.Budget.Acquire(ctx, int64(len(s.Buffer))+maxPeekSize+int64(maxOverlap))
		defer release()
	}

	var (
		// totalOffset is the absolute byte offset of the next byte to be
		// consumed from the reader.
		totalOffset int64
		// totalLines is the number of newlines consumed so far, i.e. in
		// the stream prefix [0, totalOffset).
		totalLines int
		// carryLineStart is the absolute offset of the start of the line
		// containing carry[0] (0 when no newline has been seen yet). It
		// lets fragments that begin mid-line still report columns
		// relative to the true line start.
		carryLineStart int64
		// carry is the bounded overlap window: the masked suffix of the
		// previous fragment, prepended to the next one.
		carry []byte
		// carryLines is the number of newlines inside carry.
		carryLines int
		// binary is true once the content has been classified as binary.
		binary bool
		// checkedType guards the one-time filetype sniffing.
		checkedType bool
		// undecidableMarked ensures the "context window exceeded"
		// truncation marker is only emitted once per stream.
		undecidableMarked bool
	)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		fragment := Fragment{
			FilePath: s.FullPath(),
		}

		n, err := io.ReadFull(reader, s.Buffer)
		if err == io.ErrUnexpectedEOF {
			// Partial final read: treat like io.EOF with data.
			err = io.EOF
		}
		if n == 0 {
			if err != nil && err != io.EOF {
				// Mid-stream read failure: the fragments yielded so far
				// (and their findings) remain valid. Surface a truncation
				// marker instead of failing the whole scan.
				return yield(fragment, &TruncatedError{
					Path:   s.FullPath(),
					Offset: totalOffset,
					Reason: "read-error",
					Err:    err,
				})
			}

			return nil
		}

		// Only check the filetype at the start of file.
		if !checkedType {
			checkedType = true

			// TODO: could other optimizations be introduced here?
			if mimetype, terr := filetype.Match(s.Buffer[:n]); terr != nil {
				return yield(
					fragment,
					fmt.Errorf("could not read file: could not determine type: %w", terr),
				)
			} else if mimetype.MIME.Type == "application" {
				if !s.ScanBinary {
					logging.Debug().
						Str("mime_type", mimetype.MIME.Value).
						Str("path", s.FullPath()).
						Msgf("skipping binary file")

					return nil
				}
				binary = true
			} else if s.ScanBinary && looksBinary(s.Buffer[:n]) {
				// No-extension content (e.g. firmware images) that the
				// MIME sniffers cannot classify: fall back to the NUL
				// heuristic so it is scanned as printable segments.
				binary = true
			}
		}

		// Try to split chunks across large areas of whitespace, if possible.
		// A peek error does not discard the data already read: the partial
		// chunk is still yielded below, followed by a truncation marker.
		peekBuf := bytes.NewBuffer(s.Buffer[:n])
		exhausted, perr := readUntilSafeBoundaryLimit(reader, n, maxPeekSize, peekBuf)

		chunk := peekBuf.Bytes()
		chunkOffset := totalOffset
		totalOffset += int64(len(chunk))
		chunkLines := bytes.Count(chunk, newlineByte)

		// Assemble the fragment: bounded overlap window + new data. When
		// no overlap is carried (the common case: the previous chunk
		// ended at a safe boundary) the chunk is used in place, keeping
		// allocations identical to the non-overlapping reader.
		var raw []byte
		if len(carry) == 0 {
			raw = chunk
		} else {
			// The copy also detaches the fragment contents from
			// s.Buffer, which the next read reuses.
			raw = make([]byte, 0, len(carry)+len(chunk))
			raw = append(raw, carry...)
			raw = append(raw, chunk...)
		}

		if binary {
			// Scan binary content as printable segments: mask
			// non-printable bytes in place (length-preserving, so byte
			// offsets still map to the original stream).
			maskNonPrintable(raw)
		}

		fragment.Raw = string(raw)
		fragment.Bytes = raw
		fragment.Offset = chunkOffset - int64(len(carry))
		fragment.OffsetValid = true
		fragment.OverlapBytes = len(carry)
		fragment.StartLine = totalLines - carryLines + 1
		fragment.Binary = binary
		// The fragment's first line starts at carryLineStart unless a
		// newline inside the fragment ends it earlier; in that case the
		// in-fragment newline is used and LineStartOffset is not needed.
		fragment.LineStartOffset = carryLineStart

		if len(s.Symlink) > 0 {
			fragment.SymlinkFile = s.Symlink
		}

		if isWindows {
			fragment.FilePath = filepath.ToSlash(fragment.FilePath)
			fragment.SymlinkFile = filepath.ToSlash(s.Symlink)
			fragment.WindowsFilePath = s.FullPath()
		}

		// Update line/offset bookkeeping: only the new (non-overlap) data
		// advances the counters, so positions are derived from cumulative
		// byte offsets rather than per-chunk line sums.
		totalLines += chunkLines

		// Compute the carry window for the next fragment. The window is
		// only needed when this chunk was cut at a forced (unsafe)
		// position: chunks ending at a safe whitespace boundary cannot
		// split a secret, so no overlap is carried and scanning costs
		// stay identical to the non-overlapping reader. Forced cuts carry
		// up to maxOverlap bytes so secrets straddling the cut are still
		// detected; multi-byte UTF-8 sequences split at the boundary are
		// always inside this window (maxOverlap >> 4 bytes), so the next
		// fragment sees them whole again.
		rawStart := chunkOffset - int64(len(carry))
		carryLen := 0
		if exhausted {
			carryLen = maxOverlap
			if len(raw) < carryLen {
				carryLen = len(raw)
			}
		}
		// Track the absolute start of the line the next fragment begins
		// in: the last newline before the carry window, or the previous
		// value if the line started even earlier.
		if i := bytes.LastIndexByte(raw[:len(raw)-carryLen], '\n'); i >= 0 {
			carryLineStart = rawStart + int64(i) + 1
		}
		carry = append(carry[:0], raw[len(raw)-carryLen:]...)
		carryLines = bytes.Count(carry, newlineByte)

		// A forced cut (no safe boundary within the peek limit) means a
		// match longer than the overlap window straddling this point can
		// neither be confirmed nor ruled out. Mark it as undecidable
		// instead of silently dropping the possibility.
		if exhausted && !undecidableMarked && err != io.EOF && perr == nil {
			undecidableMarked = true
			logging.Warn().
				Str("path", s.FullPath()).
				Int64("offset", chunkOffset+int64(len(chunk))).
				Msg("content exceeds safe-boundary window: oversized matches straddling this offset may be missed")
			if yerr := yield(Fragment{FilePath: fragment.FilePath}, &TruncatedError{
				Path:   s.FullPath(),
				Offset: chunkOffset + int64(len(chunk)),
				Reason: "context-window-exceeded",
			}); yerr != nil {
				return yerr
			}
		}

		// Done with the file!
		if err == io.EOF {
			return yield(fragment, nil)
		}

		// A read error (during read or peek) with data: scan what we have,
		// then mark the result incomplete instead of failing the whole scan.
		if err != nil || perr != nil {
			if yerr := yield(fragment, nil); yerr != nil {
				return yerr
			}
			readErr := err
			if readErr == nil {
				readErr = perr
			}
			return yield(Fragment{FilePath: fragment.FilePath}, &TruncatedError{
				Path:   s.FullPath(),
				Offset: totalOffset,
				Reason: "read-error",
				Err:    readErr,
			})
		}

		if yerr := yield(fragment, nil); yerr != nil {
			return yerr
		}
	}
}

var newlineByte = []byte{'\n'}

// FullPath returns the File.Path with any preceding outer paths
func (s *File) FullPath() string {
	if len(s.outerPaths) > 0 {
		return strings.Join(
			// outerPaths have already been normalized to slash
			append(s.outerPaths, s.Path),
			InnerPathSeparator,
		)
	}

	return s.Path
}
