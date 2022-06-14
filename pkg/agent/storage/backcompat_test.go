package storage_test

import (
	"crypto/x509"
	"testing"

	"github.com/spiffe/spire/pkg/agent/storage"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

func TestBackcompatLoadBundle(t *testing.T) {
	testLoadBundle(t, makeBackcompatStorage)

	t.Run("restore from legacy after downgrade", func(t *testing.T) {
		dir := spiretest.TempDir(t)
		backcompat := makeBackcompatStorage(t, dir)
		require.NoError(t, backcompat.StoreBundle([]*x509.Certificate{testCert}))
		legacy := storage.LegacyDir(dir)
		bundle, err := legacy.LoadBundle()
		require.NoError(t, err)
		require.Equal(t, []*x509.Certificate{testCert}, bundle)
	})
}

func TestBackcompatLoadSVID(t *testing.T) {
	testLoadSVID(t, makeBackcompatStorage)

	t.Run("restore from legacy after downgrade", func(t *testing.T) {
		dir := spiretest.TempDir(t)
		backcompat := makeBackcompatStorage(t, dir)
		require.NoError(t, backcompat.StoreSVID([]*x509.Certificate{testCert}))
		legacy := storage.LegacyDir(dir)
		bundle, err := legacy.LoadSVID()
		require.NoError(t, err)
		require.Equal(t, []*x509.Certificate{testCert}, bundle)
	})
}

func makeBackcompatStorage(t *testing.T, dir string) storage.Storage {
	sto, err := storage.Backcompat(dir)
	require.NoError(t, err)
	return sto
}
