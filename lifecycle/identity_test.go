package lifecycle

import (
	"strings"
	"testing"
)

func TestCanonicalSecretForms(t *testing.T) {
	tests := []struct {
		name   string
		inputs []string
		want   string
	}{
		{
			name:   "plain and trimmed",
			inputs: []string{"  sk_live_ABC123  ", "sk_live_ABC123"},
			want:   "sk_live_ABC123",
		},
		{
			name:   "quotes",
			inputs: []string{`"sk_live_ABC123"`, `'sk_live_ABC123'`, "sk_live_ABC123"},
			want:   "sk_live_ABC123",
		},
		{
			name:   "line split",
			inputs: []string{"sk_live_ABC\n123", "sk_live_ABC 123", "sk_live_ABC\r\n123", "sk_live_ABC\t123"},
			want:   "sk_live_ABC123",
		},
		{
			name:   "base64 wrapped",
			inputs: []string{"c2tfbGl2ZV9BQkMxMjM=", "sk_live_ABC123"},
			want:   "sk_live_ABC123",
		},
		{
			name:   "base64url wrapped",
			inputs: []string{"c2tfbGl2ZV9BQkMxMjM", "sk_live_ABC123"},
			want:   "sk_live_ABC123",
		},
		{
			name:   "hex wrapped",
			inputs: []string{"736b5f6c6976655f414243313233", "sk_live_ABC123"},
			want:   "sk_live_ABC123",
		},
		{
			name:   "percent escaped",
			inputs: []string{"sk_live_%41%42%43%31%32%33", "sk_live_ABC123"},
			want:   "sk_live_ABC123",
		},
		{
			name:   "backslash escapes",
			inputs: []string{`sk_live_ABC123`, "sk_live_ABC123"},
			want:   "sk_live_ABC123",
		},
		{
			name:   "escaped line break",
			inputs: []string{`sk_live_ABC\n123`, "sk_live_ABC123"},
			want:   "sk_live_ABC123",
		},
		{
			name:   "unicode escape",
			inputs: []string{`sk_live_ABC123`, "sk_live_ABC123"},
			want:   "sk_live_ABC123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, in := range tt.inputs {
				if got := CanonicalSecret(in); got != tt.want {
					t.Errorf("CanonicalSecret(%q) = %q, want %q", in, got, tt.want)
				}
			}
		})
	}
}

func TestCanonicalSecretDoesNotOverNormalize(t *testing.T) {
	// Values that merely look encoded must not be unwrapped, and distinct
	// secrets must stay distinct.
	cases := []string{
		"not-hex-and-not-base64!!!",
		"AKIAIOSFODNN7EXAMPLE",
		"AKIAIOSFODNN7EXAMPLF",
		`foo\qbar\qbaz`,
		"100%",
		"%zz",
	}
	for _, c := range cases {
		if got := CanonicalSecret(c); got != c {
			t.Errorf("CanonicalSecret(%q) = %q, want unchanged", c, got)
		}
	}
}

func TestHasherRepositoryScoped(t *testing.T) {
	a := NewHasher("repo-a")
	b := NewHasher("repo-b")

	secret := "sk_live_ABC123"
	if a.Digest(secret) == b.Digest(secret) {
		t.Fatalf("same secret in two repositories produced the same identifier")
	}
	if a.Digest(secret) != a.Digest(secret) {
		t.Fatalf("digest is not stable across calls")
	}
	if !strings.HasPrefix(a.Digest(secret), "glsk_") {
		t.Errorf("digest %q lacks the expected prefix", a.Digest(secret))
	}
	if strings.Contains(a.Digest(secret), secret) {
		t.Errorf("digest leaks the secret")
	}

	// Equivalent representations hash identically within a repository.
	if a.Digest("sk_live_ABC123") != a.Digest("sk_live_ABC%20123") {
		t.Errorf("equivalent representations produced different identifiers")
	}
	if a.Digest("sk_live_ABC123") != a.Digest("c2tfbGl2ZV9BQkMxMjM=") {
		t.Errorf("base64 representation produced a different identifier")
	}
}

func TestHasherPepper(t *testing.T) {
	plain := NewHasherWithPepper("repo-a", "")
	peppered := NewHasherWithPepper("repo-a", "operator-secret")
	secret := "sk_live_ABC123"
	if plain.Digest(secret) == peppered.Digest(secret) {
		t.Fatalf("pepper did not change the identifier")
	}
	if peppered.Digest(secret) != peppered.Digest(secret) {
		t.Fatalf("peppered digest is not stable")
	}
}

func TestRepoFingerprintIgnoresCheckoutPath(t *testing.T) {
	roots := []string{"abc123", "def456"}
	remote := "https://github.com/acme/demo.git"
	a := RepoFingerprint(KindGit, "/home/alice/demo", roots, remote)
	b := RepoFingerprint(KindGit, "/home/bob/checkout", roots, "file:///tmp/elsewhere")
	if a != b {
		t.Errorf("git fingerprint depends on the local path or remote URL")
	}

	// Different repositories must differ even at the same path.
	c := RepoFingerprint(KindGit, "/home/alice/demo", []string{"999999"}, remote)
	if a == c {
		t.Errorf("different root commits produced the same fingerprint")
	}

	// Directory scans have no git identity; the path is the identity.
	d := RepoFingerprint(KindDirectory, "/srv/a", nil, "")
	e := RepoFingerprint(KindDirectory, "/srv/b", nil, "")
	if d == e {
		t.Errorf("directory fingerprints should differ by path")
	}
}

func TestRemoteURLCredentialsStripped(t *testing.T) {
	in := "https://user:token@github.com/acme/demo.git"
	got := sanitizeRemoteURL(in)
	if strings.Contains(got, "token") || strings.Contains(got, "user:") {
		t.Errorf("credentials not stripped: %q", got)
	}
	if !strings.Contains(got, "github.com/acme/demo.git") {
		t.Errorf("host/path lost: %q", got)
	}
}
