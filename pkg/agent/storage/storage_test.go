package storage

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

var (
	certsA, _ = pemutil.ParseCertificates([]byte(`
-----BEGIN CERTIFICATE-----                                                                                                                                                                                                                                       
MIIBFzCBvaADAgECAgEBMAoGCCqGSM49BAMCMBExDzANBgNVBAMTBkNFUlQtQTAi                                                                                                                                                                                                  
GA8wMDAxMDEwMTAwMDAwMFoYDzAwMDEwMTAxMDAwMDAwWjARMQ8wDQYDVQQDEwZD                                                                                                                                                                                                  
RVJULUEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS6qfd5FtzLYW+p7NgjqqJu                                                                                                                                                                                                  
EAyewtzk4ypsM7PfePnL+45U+mSSypopiiyXvumOlU3uIHpnVhH+dk26KXGHeh2i                                                                                                                                                                                                  
owIwADAKBggqhkjOPQQDAgNJADBGAiEAom6HzKAkMs3wiQJUwJiSjp9q9PHaWgGh                                                                                                                                                                                                  
m7Ins/ReHk4CIQCncVaUC6i90RxiUJNfxPPMwSV9kulsj67reucS+UkBIw==                                                                                                                                                                                                      
-----END CERTIFICATE-----                                                                                                                                                                                                                                         
`))

	certsB, _ = pemutil.ParseCertificates([]byte(`
-----BEGIN CERTIFICATE-----                                                                                                                                                                                                                                       
MIIBFTCBvaADAgECAgEBMAoGCCqGSM49BAMCMBExDzANBgNVBAMTBkNFUlQtQjAi                                                                                                                                                                                                  
GA8wMDAxMDEwMTAwMDAwMFoYDzAwMDEwMTAxMDAwMDAwWjARMQ8wDQYDVQQDEwZD                                                                                                                                                                                                  
RVJULUIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS6qfd5FtzLYW+p7NgjqqJu                                                                                                                                                                                                  
EAyewtzk4ypsM7PfePnL+45U+mSSypopiiyXvumOlU3uIHpnVhH+dk26KXGHeh2i                                                                                                                                                                                                  
owIwADAKBggqhkjOPQQDAgNHADBEAiBwFhJ/GSSuPTR9cn/R4RhK/FMdboO/nOFJ                                                                                                                                                                                                  
banfBh0KjQIgdAKbWkRi8d/iE7wMaW4AqGXAsgpqS3I5nQCOb8RXn0M=                                                                                                                                                                                                          
-----END CERTIFICATE-----                                                                                                                                                                                                                                         
`))
)

func TestBundle(t *testing.T) {
	t.Run("load from empty storage", func(t *testing.T) {
		dir := spiretest.TempDir(t)

		sto := openStorage(t, dir)
		actual, err := sto.LoadBundle()
		require.True(t, errors.Is(err, ErrNotCached))
		require.Nil(t, actual)
	})

	t.Run("load from same storage instance", func(t *testing.T) {
		dir := spiretest.TempDir(t)

		sto := openStorage(t, dir)
		require.NoError(t, sto.StoreBundle(certsA))

		actual, err := sto.LoadBundle()
		require.NoError(t, err)
		require.Equal(t, certsA, actual)
	})

	t.Run("load from new storage instance", func(t *testing.T) {
		dir := spiretest.TempDir(t)

		sto := openStorage(t, dir)
		require.NoError(t, sto.StoreBundle(certsA))

		sto = openStorage(t, dir)
		actual, err := sto.LoadBundle()
		require.NoError(t, err)
		require.Equal(t, certsA, actual)
	})

	t.Run("populate from legacy after upgrade", func(t *testing.T) {
		// Populate legacy bundle
		dir := spiretest.TempDir(t)
		require.NoError(t, storeLegacyBundle(dir, certsA))

		// Open storage, simulating an upgrade
		sto := openStorage(t, dir)

		// Ensure the legacy bundle exists
		actual, err := sto.LoadBundle()
		require.NoError(t, err)
		require.Equal(t, certsA, actual)
	})

	t.Run("restore from legacy after downgrade", func(t *testing.T) {
		dir := spiretest.TempDir(t)

		// Open storage and store the bundle
		sto := openStorage(t, dir)
		require.NoError(t, sto.StoreBundle(certsA))

		// Assert the legacy bundle has been stored
		actual, _, err := loadLegacyBundle(dir)
		require.NoError(t, err)
		require.Equal(t, certsA, actual)
	})

	t.Run("restore from legacy after downgrade/upgrade", func(t *testing.T) {
		dir := spiretest.TempDir(t)

		// Store to legacy storage simulating state before upgrade
		require.NoError(t, storeLegacyBundle(dir, certsA))

		// Open storage to simulate state after upgrade and assert legacy data
		// is observed.
		sto := openStorage(t, dir)
		actual, err := sto.LoadBundle()
		require.NoError(t, err)
		require.Equal(t, certsA, actual)

		// Write values to legacy storage simulating change after downgrade
		require.NoError(t, storeLegacyBundle(dir, certsB))

		// To be resilient against timing, manually adjust the mtime on the
		// legacy data to ensure the mtime is after the storage data.
		now := time.Now()
		require.NoError(t, os.Chtimes(legacyBundlePath(dir), now, now.Add(time.Second)))

		// Reload the sto storage (simulating the upgrade after
		// downgrade) and assert new cert is observed.
		sto = openStorage(t, dir)
		actual, err = sto.LoadBundle()
		require.NoError(t, err)
		require.Equal(t, certsB, actual)
	})
}

func TestSVID(t *testing.T) {
	t.Run("load from empty storage", func(t *testing.T) {
		dir := spiretest.TempDir(t)

		sto := openStorage(t, dir)
		actual, reattestable, err := sto.LoadSVID()
		require.True(t, errors.Is(err, ErrNotCached))
		require.Nil(t, actual)
		require.False(t, reattestable)
	})

	t.Run("load from same storage instance", func(t *testing.T) {
		dir := spiretest.TempDir(t)

		sto := openStorage(t, dir)
		require.NoError(t, sto.StoreSVID(certsA, true))

		actual, reattestable, err := sto.LoadSVID()
		require.NoError(t, err)
		require.Equal(t, certsA, actual)
		require.True(t, reattestable)
	})

	t.Run("load from new storage instance", func(t *testing.T) {
		dir := spiretest.TempDir(t)

		sto := openStorage(t, dir)
		require.NoError(t, sto.StoreSVID(certsA, true))

		sto = openStorage(t, dir)
		actual, reattestable, err := sto.LoadSVID()
		require.NoError(t, err)
		require.Equal(t, certsA, actual)
		require.True(t, reattestable)
	})

	t.Run("populate from legacy after upgrade", func(t *testing.T) {
		// Populate legacy SVID
		dir := spiretest.TempDir(t)
		require.NoError(t, storeLegacySVID(dir, certsA))

		// Open storage, simulating an upgrade
		sto := openStorage(t, dir)

		// Ensure the legacy SVID exists
		actual, reattestable, err := sto.LoadSVID()
		require.NoError(t, err)
		require.Equal(t, certsA, actual)
		require.False(t, reattestable)
	})

	t.Run("restore from legacy after downgrade", func(t *testing.T) {
		dir := spiretest.TempDir(t)

		// Open storage and store the SVID
		sto := openStorage(t, dir)
		require.NoError(t, sto.StoreSVID(certsA, false))

		// Assert the legacy SVID has been stored
		actual, _, err := loadLegacySVID(dir)
		require.NoError(t, err)
		require.Equal(t, certsA, actual)
	})

	t.Run("restore from legacy after downgrade/upgrade", func(t *testing.T) {
		dir := spiretest.TempDir(t)

		// Store to legacy storage simulating state before upgrade
		require.NoError(t, storeLegacySVID(dir, certsA))

		// Open storage to simulate state after upgrade and assert legacy data
		// is observed.
		sto := openStorage(t, dir)
		actual, reattestable, err := sto.LoadSVID()
		require.NoError(t, err)
		require.Equal(t, certsA, actual)
		require.False(t, reattestable)

		// Write values to legacy storage simulating change after downgrade
		require.NoError(t, storeLegacySVID(dir, certsB))

		// To be resilient against timing, manually adjust the mtime on the
		// legacy data to ensure the mtime is after the storage data.
		now := time.Now()
		require.NoError(t, os.Chtimes(legacySVIDPath(dir), now, now.Add(time.Second)))

		// Reload the sto storage (simulating the upgrade after
		// downgrade) and assert new cert is observed.
		sto = openStorage(t, dir)
		actual, reattestable, err = sto.LoadSVID()
		require.NoError(t, err)
		require.Equal(t, certsB, actual)
		require.False(t, reattestable)
	})

	t.Run("delete from empty storage", func(t *testing.T) {
		dir := spiretest.TempDir(t)

		sto := openStorage(t, dir)
		require.NoError(t, sto.DeleteSVID())

		actual, reattestable, err := sto.LoadSVID()
		require.True(t, errors.Is(err, ErrNotCached))
		require.Nil(t, actual)
		require.False(t, reattestable)
	})

	t.Run("delete from populated storage", func(t *testing.T) {
		dir := spiretest.TempDir(t)

		sto := openStorage(t, dir)
		require.NoError(t, sto.StoreSVID(certsA, true))
		require.NoError(t, sto.DeleteSVID())

		actual, reattestable, err := sto.LoadSVID()
		require.True(t, errors.Is(err, ErrNotCached))
		require.Nil(t, actual)
		require.False(t, reattestable)
	})

	t.Run("delete from populated storage with new instances", func(t *testing.T) {
		dir := spiretest.TempDir(t)

		sto := openStorage(t, dir)
		require.NoError(t, sto.StoreSVID(certsA, true))

		sto = openStorage(t, dir)
		require.NoError(t, sto.DeleteSVID())

		sto = openStorage(t, dir)
		actual, reattestable, err := sto.LoadSVID()
		require.True(t, errors.Is(err, ErrNotCached))
		require.Nil(t, actual)
		require.False(t, reattestable)
	})
}

func openStorage(t *testing.T, dir string) Storage {
	sto, err := Open(dir)
	require.NoError(t, err)
	return sto
}
