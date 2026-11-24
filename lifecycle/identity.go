package lifecycle

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// digestPrefix makes it obvious that an identifier is a salted lifecycle
// digest and not a secret that can be looked up in a rainbow table.
const digestPrefix = "glsk_"

// saltDomain separates lifecycle fingerprints from any other SHA-256 use in
// gitleaks. Bumping it intentionally changes all identifiers.
const saltDomain = "gitleaks/lifecycle/v1"

// Hasher derives salted, repository-scoped identifiers for canonical secrets.
//
// The salt is derived from repository identity (root commits + remote URL) or
// supplied by the operator. The same secret in two different repositories
// therefore gets two different identifiers, while repeated scans of the same
// repository get byte-identical identifiers.
type Hasher struct {
	salt [32]byte
}

// NewHasher creates a Hasher from a repository fingerprint.
func NewHasher(repoFingerprint string) *Hasher {
	return NewHasherWithPepper(repoFingerprint, "")
}

// NewHasherWithPepper creates a Hasher from a repository fingerprint and an
// optional operator-supplied pepper. The pepper is mixed with the repository
// fingerprint rather than replacing it, so identifiers still cannot be
// reused across repositories.
func NewHasherWithPepper(repoFingerprint, pepper string) *Hasher {
	seed := saltDomain + "\x00" + repoFingerprint
	if pepper != "" {
		seed += "\x00" + pepper
	}
	h := &Hasher{salt: sha256.Sum256([]byte(seed))}
	return h
}

// Digest returns the salted identifier for a raw secret.
func (h *Hasher) Digest(secret string) string {
	canonical := CanonicalSecret(secret)
	sum := sha256.New()
	sum.Write(h.salt[:])
	sum.Write([]byte{0})
	sum.Write([]byte(canonical))
	return digestPrefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum.Sum(nil)))
}

// Canonical returns the normalized form used for identity comparisons. It is
// exposed so tests and tools can reason about grouping without hashing.
func (h *Hasher) Canonical(secret string) string {
	return CanonicalSecret(secret)
}

// CanonicalSecret normalizes encoded, escaped and line-split representations
// of a secret into one deterministic value.
//
// Normalization is deliberately conservative about what it wraps: it only
// unwraps a value when the whole value decodes cleanly into printable ASCII.
// It never lowercases or otherwise reduces the entropy of the secret.
func CanonicalSecret(secret string) string {
	s := strings.TrimSpace(secret)
	if s == "" {
		return ""
	}

	for depth := 0; depth < 4; depth++ {
		next := canonicalPass(s)
		if next == s {
			break
		}
		s = next
	}
	return s
}

func canonicalPass(s string) string {
	s = unescapeEscapes(s)

	// Requirement: a secret split across lines (or with inserted whitespace)
	// is the same secret. Strip all Unicode whitespace.
	s = stripSpace(s)

	// A captured value is often wrapped in the quotes it was declared with.
	s = trimMatchingQuotes(s)

	if decoded, ok := decodeWrapped(s); ok {
		return decoded
	}
	return s
}

func stripSpace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func trimMatchingQuotes(s string) string {
	if len(s) < 2 {
		return s
	}
	first, last := s[0], s[len(s)-1]
	if first != last {
		return s
	}
	switch first {
	case '"', '\'', '`':
		inner := s[1 : len(s)-1]
		if inner != "" {
			return inner
		}
	}
	return s
}

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func hexNibble(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}

// unescapeEscapes resolves the escape forms commonly used to wrap secrets:
// percent-encoding, Go/C/JSON escapes, \xNN byte escapes and \uNNNN/U+NNNN
// code points. Invalid escapes are preserved verbatim.
func unescapeEscapes(s string) string {
	if !strings.ContainsAny(s, `\%`) && !strings.Contains(s, "U+") {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); i++ {
		c := s[i]

		if c == '%' && i+2 < len(s) && isHexByte(s[i+1]) && isHexByte(s[i+2]) {
			n1, _ := hexNibble(s[i+1])
			n2, _ := hexNibble(s[i+2])
			v := n1<<4 | n2
			if printableASCII(v) {
				b.WriteByte(v)
				i += 2
				continue
			}
		}

		if c == 'U' && i+5 < len(s) && s[i+1] == '+' {
			if r, ok := parseCodePoint(s[i+2 : i+6]); ok {
				b.WriteRune(r)
				i += 5
				continue
			}
		}

		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}

		switch s[i+1] {
		case 'n':
			b.WriteByte('\n')
			i++
		case 'r':
			b.WriteByte('\r')
			i++
		case 't':
			b.WriteByte('\t')
			i++
		case 'b':
			b.WriteByte('\b')
			i++
		case 'f':
			b.WriteByte('\f')
			i++
		case 'v':
			b.WriteByte('\v')
			i++
		case '0':
			b.WriteByte(0)
			i++
		case '\\', '"', '\'', '/', ',':
			b.WriteByte(s[i+1])
			i++
		case 'x':
			if i+3 < len(s) && isHexByte(s[i+2]) && isHexByte(s[i+3]) {
				n1, _ := hexNibble(s[i+2])
				n2, _ := hexNibble(s[i+3])
				b.WriteByte(n1<<4 | n2)
				i += 3
			} else {
				b.WriteByte(c)
			}
		case 'u':
			if i+5 < len(s) {
				if r, ok := parseCodePoint(s[i+2 : i+6]); ok {
					b.WriteRune(r)
					i += 5
				} else {
					b.WriteByte(c)
				}
			} else {
				b.WriteByte(c)
			}
		case 'U':
			if i+9 < len(s) {
				if r, ok := parseCodePoint(s[i+2 : i+10]); ok {
					b.WriteRune(r)
					i += 9
				} else {
					b.WriteByte(c)
				}
			} else {
				b.WriteByte(c)
			}
		default:
			// Keep unknown escapes (e.g. a Windows path) untouched.
			b.WriteByte(c)
		}
	}
	return b.String()
}

func parseCodePoint(s string) (rune, bool) {
	if len(s) < 4 || len(s) > 8 {
		return 0, false
	}
	var v int64
	for i := 0; i < len(s); i++ {
		n, ok := hexNibble(s[i])
		if !ok {
			return 0, false
		}
		v = v<<4 | int64(n)
	}
	if v <= 0 || v > unicode.MaxRune {
		return 0, false
	}
	return rune(v), true
}

func printableASCII(b byte) bool {
	return b >= 0x20 && b <= 0x7e
}

func printableASCIIBytes(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if !printableASCII(c) && c != '\n' && c != '\r' && c != '\t' {
			return false
		}
	}
	return true
}

// decodeWrapped decodes a value that is entirely wrapped in a common encoding.
// It reports false when the value is not cleanly decodable.
func decodeWrapped(s string) (string, bool) {
	if len(s) < 8 {
		return "", false
	}

	if decoded, ok := decodeBase64Wrapped(s); ok {
		return decoded, true
	}
	if decoded, ok := decodeHexWrapped(s); ok {
		return decoded, true
	}
	return "", false
}

func decodeBase64Wrapped(s string) (string, bool) {
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '+', c == '/', c == '-', c == '_', c == '=':
		default:
			return "", false
		}
	}

	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		decoded, err := enc.DecodeString(s)
		if err != nil || len(decoded) < 4 {
			continue
		}
		if printableASCIIBytes(decoded) {
			return string(decoded), true
		}
	}
	return "", false
}

func decodeHexWrapped(s string) (string, bool) {
	if len(s)%2 != 0 {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		if !isHexByte(s[i]) {
			return "", false
		}
	}
	decoded, err := hex.DecodeString(s)
	if err != nil || len(decoded) < 4 {
		return "", false
	}
	if printableASCIIBytes(decoded) {
		return string(decoded), true
	}
	return "", false
}

// RepoFingerprint derives the stable, repository-scoped salt seed used by the
// Hasher. For directory scans (no history) it falls back to the absolute
// source path, which still keeps identifiers from being reused across
// unrelated trees.
func RepoFingerprint(kind Kind, sourcePath string, rootCommits []string, remoteURL string) string {
	// Git identity comes only from repository content (root commit SHAs).
	// The checkout path and remote URL are deliberately excluded: re-cloning
	// or mirroring the same repository must yield the same identifiers, while
	// an unrelated repository cannot share them without sharing history.
	_ = remoteURL
	parts := []string{string(kind)}
	if len(rootCommits) > 0 {
		roots := append([]string(nil), rootCommits...)
		sort.Strings(roots)
		parts = append(parts, strings.Join(roots, ","))
	} else {
		parts = append(parts, sourcePath)
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(parts, "\x00"))))
}

func sanitizeRemoteURL(u string) string {
	u = strings.TrimSpace(u)
	if i := strings.Index(u, "://"); i >= 0 {
		scheme := u[:i+3]
		rest := u[i+3:]
		if at := strings.Index(rest, "@"); at >= 0 && at < strings.Index(rest+"/", "/")+1 {
			rest = rest[at+1:]
		}
		return scheme + rest
	}
	// scp-like syntax: user@host:path
	if at := strings.Index(u, "@"); at >= 0 {
		return u[at+1:]
	}
	return u
}
