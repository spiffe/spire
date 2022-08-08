package util

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_GetSHA256Digest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(path, []byte("some data"), 0600))
	hash, err := GetSHA256Digest(path, -1)
	require.NoError(t, err)
	require.Equal(t, "1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee", hash)
}

func Test_GetSHA256Digest_BelowLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(path, []byte("some data"), 0600))
	hash, err := GetSHA256Digest(path, 100)
	require.NoError(t, err)
	require.Equal(t, "1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee", hash)
}

func Test_GetSHA256Digest_AboveLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(path, []byte("some data"), 0600))
	hash, err := GetSHA256Digest(path, 5)
	require.ErrorContains(t, err, "exceeds size limit")
	require.Empty(t, hash)
}

func Test_GetSHA256Digest_FileMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	hash, err := GetSHA256Digest(path, 5)
	require.Error(t, err)
	require.Empty(t, hash)
}
