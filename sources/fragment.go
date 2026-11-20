package sources

// Fragment represents a fragment of a source with its meta data
type Fragment struct {
	// Raw is the raw content of the fragment
	Raw string

	Bytes []byte

	// FilePath is the path to the file if applicable.
	// The path separator MUST be normalized to `/`.
	FilePath    string
	SymlinkFile string
	// WindowsFilePath is the path with the original separator.
	// This provides a backwards-compatible solution to https://github.com/gitleaks/gitleaks/issues/1565.
	WindowsFilePath string `json:"-"` // TODO: remove this in v9.

	// CommitSHA is the SHA of the commit if applicable
	CommitSHA string // TODO: remove this in v9 and use CommitInfo instead

	// StartLine is the line number this fragment starts on
	StartLine int

	// Offset is the absolute byte offset of Raw[0] within the source
	// stream (file, archive member, stdin, ...). It is only meaningful
	// when OffsetValid is true.
	Offset int64

	// OffsetValid indicates that Offset is anchored to the source byte
	// stream. Sources that cannot provide byte offsets (e.g. git diff
	// output) leave this unset.
	OffsetValid bool

	// LineStartOffset is the absolute byte offset of the start of the
	// line this fragment begins in. It equals Offset when the fragment
	// starts at a line boundary; when the fragment begins mid-line (the
	// line started in earlier content) it points at the true line start,
	// so columns can be expressed relative to the original content.
	// Only meaningful when OffsetValid is true.
	LineStartOffset int64

	// OverlapBytes is the number of leading bytes of Raw that were already
	// yielded at the tail of the previous fragment. It is a bounded
	// cross-chunk context window so that secrets split across read
	// boundaries are still detected. Matches that end within this window
	// must be treated as duplicates of the previous fragment.
	OverlapBytes int

	// Binary indicates the fragment came from content detected as binary.
	// Non-printable bytes in Raw have been masked with '.' so findings
	// never contain raw binary; positions remain byte-accurate because
	// masking is length-preserving.
	Binary bool

	// CommitInfo captures additional information about the git commit if applicable
	CommitInfo *CommitInfo

	InheritedFromFinding bool // Indicates if this fragment is inherited from a finding
}
