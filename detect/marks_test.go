package detect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarksLifecycleSuppressListRevoke(t *testing.T) {
	path := filepath.Join(t.TempDir(), "marks.json")
	store, err := NewMarksStore(path)
	require.NoError(t, err)

	fp := "svc/config.yaml:short-prefixed-token:3"
	require.NoError(t, store.Suppress(fp, "non-secret build id"))
	assert.True(t, store.IsSuppressed(fp))
	assert.False(t, store.IsRevoked(fp))

	// A fresh store reading the same file must observe the persisted mark.
	reopened, err := NewMarksStore(path)
	require.NoError(t, err)
	assert.True(t, reopened.IsSuppressed(fp))

	require.NoError(t, reopened.Revoke(fp))
	assert.False(t, reopened.IsSuppressed(fp))
	assert.True(t, reopened.IsRevoked(fp))

	// Revocation is also durable.
	reopened2, err := NewMarksStore(path)
	require.NoError(t, err)
	assert.True(t, reopened2.IsRevoked(fp))

	// Re-suppressing a revoked fingerprint moves it back.
	require.NoError(t, reopened2.Suppress(fp, ""))
	assert.True(t, reopened2.IsSuppressed(fp))
}

func TestMarksRevokeUnknownFingerprintErrors(t *testing.T) {
	store, err := NewMarksStore(filepath.Join(t.TempDir(), "marks.json"))
	require.NoError(t, err)
	assert.ErrorIs(t, store.Revoke("file:rule:1"), ErrMarkNotFound)
}

func TestMarksRejectEmptyFingerprint(t *testing.T) {
	store, err := NewMarksStore(filepath.Join(t.TempDir(), "marks.json"))
	require.NoError(t, err)
	assert.ErrorIs(t, store.Suppress("", "note"), ErrInvalidMark)
}

func TestMarksMissingFileIsEmptyStore(t *testing.T) {
	store, err := NewMarksStore(filepath.Join(t.TempDir(), "does-not-exist.json"))
	require.NoError(t, err)
	assert.Empty(t, store.List())
}

func TestMarksRejectUnsupportedSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "marks.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"schema_version":99,"marks":[]}`), 0o600))
	_, err := NewMarksStore(path)
	assert.Error(t, err)
}

func TestMarksListIsStableOrder(t *testing.T) {
	store, err := NewMarksStore(filepath.Join(t.TempDir(), "marks.json"))
	require.NoError(t, err)
	fps := []string{"b:r:2", "a:r:1", "c:r:3"}
	for _, fp := range fps {
		require.NoError(t, store.Suppress(fp, ""))
	}
	got := store.List()
	require.Len(t, got, 3)
	assert.Equal(t, "a:r:1", got[0].Fingerprint)
	assert.Equal(t, "b:r:2", got[1].Fingerprint)
	assert.Equal(t, "c:r:3", got[2].Fingerprint)
}

func TestMarksInMemoryStoreWithoutPath(t *testing.T) {
	store, err := NewMarksStore("")
	require.NoError(t, err)
	require.NoError(t, store.Suppress("f:r:1", ""))
	assert.True(t, store.IsSuppressed("f:r:1"))
}
