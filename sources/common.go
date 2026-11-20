package sources

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime"

	"github.com/mholt/archives"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
)

const maxPeekSize = 25 * 1_000 // 10kb
var isWhitespace [256]bool
var isWindows = runtime.GOOS == "windows"

// TruncatedError signals that a source was only partially scanned. The
// findings produced before the truncation point are still valid; the
// error exists so callers can mark the result as incomplete instead of
// silently returning an empty or partial result.
type TruncatedError struct {
	// Path is the source path that was truncated.
	Path string
	// Offset is the byte offset at which scanning stopped, when known.
	Offset int64
	// Reason is a short machine-stable description of the limit that was
	// hit (e.g. "read-error", "archive-member-limit").
	Reason string
	// Err is the underlying error, if any.
	Err error
}

func (e *TruncatedError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("scan truncated at offset %d (%s): %v", e.Offset, e.Reason, e.Err)
	}
	return fmt.Sprintf("scan truncated at offset %d (%s)", e.Offset, e.Reason)
}

func (e *TruncatedError) Unwrap() error { return e.Err }

// IsTruncated reports whether err (or any error it wraps) is a
// TruncatedError, i.e. the associated results are incomplete.
func IsTruncated(err error) bool {
	var te *TruncatedError
	return errors.As(err, &te)
}

// maskNonPrintable replaces every byte that is not printable ASCII or
// common whitespace with '.'. The replacement is length-preserving so
// byte offsets into the original content remain valid. It is used for
// binary content so that findings never contain raw binary data while
// remaining reproducible and traceable to the original byte range.
func maskNonPrintable(data []byte) {
	for i, b := range data {
		if b == '\n' || b == '\r' || b == '\t' {
			continue
		}
		if b < 0x20 || b > 0x7e {
			data[i] = '.'
		}
	}
}

// looksBinary reports whether the sample appears to be binary content,
// using the presence of a NUL byte as the heuristic.
func looksBinary(sample []byte) bool {
	return bytes.IndexByte(sample, 0) >= 0
}

func init() {
	// define whitespace characters
	isWhitespace[' '] = true
	isWhitespace['\t'] = true
	isWhitespace['\n'] = true
	isWhitespace['\r'] = true
}

// isArchive does a light check to see if the provided path is an archive or
// compressed file. The File source already does this, so this exists mainly
// to avoid expensive calls before sending things to the File source
func isArchive(ctx context.Context, path string) bool {
	format, _, err := archives.Identify(ctx, path, nil)
	return err == nil && format != nil
}

// shouldSkipPath checks a path against all the allowlists to see if it can
// be skipped
func shouldSkipPath(cfg *config.Config, path string) bool {
	if cfg == nil {
		logging.Trace().Str("path", path).Msg("not skipping path because config is nil")
		return false
	}

	for _, a := range cfg.Allowlists {
		if a.PathAllowed(path) ||
			// TODO: Remove this in v9.
			// This is an awkward hack to mitigate https://github.com/gitleaks/gitleaks/issues/1641.
			(isWindows && a.PathAllowed(filepath.ToSlash(path))) {
			return true
		}
	}

	return false
}

// readUntilSafeBoundary consumes |f| until it finds two consecutive `\n` characters, up to |maxPeekSize|.
// This hopefully avoids splitting. (https://github.com/gitleaks/gitleaks/issues/1651)
func readUntilSafeBoundary(r *bufio.Reader, n int, maxPeekSize int, peekBuf *bytes.Buffer) error {
	_, err := readUntilSafeBoundaryLimit(r, n, maxPeekSize, peekBuf)
	return err
}

// readUntilSafeBoundaryLimit behaves like readUntilSafeBoundary but also
// reports whether the peek limit was exhausted without finding a safe
// boundary. An exhausted limit means the chunk was cut at an arbitrary
// byte position: matches longer than the cross-chunk context window that
// straddle this cut cannot be confirmed or ruled out (undecidable).
func readUntilSafeBoundaryLimit(r *bufio.Reader, n int, maxPeekSize int, peekBuf *bytes.Buffer) (exhausted bool, err error) {
	if peekBuf.Len() == 0 {
		return false, nil
	}

	// Does the buffer end in consecutive newlines?
	var (
		data         = peekBuf.Bytes()
		lastChar     = data[len(data)-1]
		newlineCount = 0 // Tracks consecutive newlines
	)

	if isWhitespace[lastChar] {
		for i := len(data) - 1; i >= 0; i-- {
			lastChar = data[i]
			if lastChar == '\n' {
				newlineCount++

				// Stop if two consecutive newlines are found
				if newlineCount >= 2 {
					return false, nil
				}
			} else if isWhitespace[lastChar] {
				// The presence of other whitespace characters (`\r`, ` `, `\t`) shouldn't reset the count.
				// (Intentionally do nothing.)
			} else {
				break
			}
		}
	}

	// If not, read ahead until we (hopefully) find some.
	newlineCount = 0
	for {
		data = peekBuf.Bytes()
		// Check if the last character is a newline.
		lastChar = data[len(data)-1]
		if lastChar == '\n' {
			newlineCount++

			// Stop if two consecutive newlines are found
			if newlineCount >= 2 {
				break
			}
		} else if isWhitespace[lastChar] {
			// The presence of other whitespace characters (`\r`, ` `, `\t`) shouldn't reset the count.
			// (Intentionally do nothing.)
		} else {
			newlineCount = 0 // Reset if a non-newline character is found
		}

		// Stop growing the buffer if it reaches maxSize
		if (peekBuf.Len() - n) >= maxPeekSize {
			exhausted = true
			break
		}

		// Read additional data into a temporary buffer
		b, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return exhausted, err
		}
		peekBuf.WriteByte(b)
	}
	return exhausted, nil
}
