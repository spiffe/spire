package storage

import (
	"errors"
	"testing"

	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

var (
	certs, _ = pemutil.ParseCertificates([]byte(`
-----BEGIN CERTIFICATE-----                                                                                                                                                                                                                                       
MIIBFzCBvaADAgECAgEBMAoGCCqGSM49BAMCMBExDzANBgNVBAMTBkNFUlQtQTAi                                                                                                                                                                                                  
GA8wMDAxMDEwMTAwMDAwMFoYDzAwMDEwMTAxMDAwMDAwWjARMQ8wDQYDVQQDEwZD                                                                                                                                                                                                  
RVJULUEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS6qfd5FtzLYW+p7NgjqqJu                                                                                                                                                                                                  
EAyewtzk4ypsM7PfePnL+45U+mSSypopiiyXvumOlU3uIHpnVhH+dk26KXGHeh2i                                                                                                                                                                                                  
owIwADAKBggqhkjOPQQDAgNJADBGAiEAom6HzKAkMs3wiQJUwJiSjp9q9PHaWgGh                                                                                                                                                                                                  
m7Ins/ReHk4CIQCncVaUC6i90RxiUJNfxPPMwSV9kulsj67reucS+UkBIw==                                                                                                                                                                                                      
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
		require.NoError(t, sto.StoreBundle(certs))

		actual, err := sto.LoadBundle()
		require.NoError(t, err)
		require.Equal(t, certs, actual)
	})

	t.Run("load from new storage instance", func(t *testing.T) {
		dir := spiretest.TempDir(t)

		sto := openStorage(t, dir)
		require.NoError(t, sto.StoreBundle(certs))

		sto = openStorage(t, dir)
		actual, err := sto.LoadBundle()
		require.NoError(t, err)
		require.Equal(t, certs, actual)
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
		require.NoError(t, sto.StoreSVID(certs, true))

		actual, reattestable, err := sto.LoadSVID()
		require.NoError(t, err)
		require.Equal(t, certs, actual)
		require.True(t, reattestable)
	})

	t.Run("load from new storage instance", func(t *testing.T) {
		dir := spiretest.TempDir(t)

		sto := openStorage(t, dir)
		require.NoError(t, sto.StoreSVID(certs, true))

		sto = openStorage(t, dir)
		actual, reattestable, err := sto.LoadSVID()
		require.NoError(t, err)
		require.Equal(t, certs, actual)
		require.True(t, reattestable)
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
		require.NoError(t, sto.StoreSVID(certs, true))
		require.NoError(t, sto.DeleteSVID())

		actual, reattestable, err := sto.LoadSVID()
		require.True(t, errors.Is(err, ErrNotCached))
		require.Nil(t, actual)
		require.False(t, reattestable)
	})

	t.Run("delete from populated storage with new instances", func(t *testing.T) {
		dir := spiretest.TempDir(t)

		sto := openStorage(t, dir)
		require.NoError(t, sto.StoreSVID(certs, true))

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
