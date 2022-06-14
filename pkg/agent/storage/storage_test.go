package storage_test

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/spiffe/spire/pkg/agent/storage"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

var (
	testCert, _ = pemutil.ParseCertificate([]byte(`-----BEGIN CERTIFICATE-----
MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBa
GA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyv
sCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXs
RxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkw
F4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09X
makw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylA
dZglS5kKnYigmwDh+/U=
-----END CERTIFICATE-----
`))
)

func testLoadBundle(t *testing.T, fn func(t *testing.T, dir string) storage.Storage) {
	dir := spiretest.TempDir(t)

	sto := fn(t, dir)

	t.Run("load from empty storage", func(t *testing.T) {
		actual, err := sto.LoadBundle()
		require.True(t, errors.Is(err, storage.ErrNotCached))
		require.Nil(t, actual)
	})

	expected := []*x509.Certificate{testCert}
	require.NoError(t, sto.StoreBundle(expected))

	t.Run("load from same storage instance", func(t *testing.T) {
		actual, err := sto.LoadBundle()
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	})

	sto = fn(t, dir)

	t.Run("load from new storage instance", func(t *testing.T) {
		actual, err := sto.LoadBundle()
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	})
}

func testLoadSVID(t *testing.T, fn func(t *testing.T, dir string) storage.Storage) {
	dir := spiretest.TempDir(t)

	sto := fn(t, dir)

	t.Run("load from empty storage", func(t *testing.T) {
		actual, err := sto.LoadSVID()
		require.True(t, errors.Is(err, storage.ErrNotCached))
		require.Nil(t, actual)
	})

	expected := []*x509.Certificate{testCert}
	require.NoError(t, sto.StoreSVID(expected))

	t.Run("load from same storage instance", func(t *testing.T) {
		actual, err := sto.LoadSVID()
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	})

	sto = fn(t, dir)

	t.Run("load from new storage instance", func(t *testing.T) {
		actual, err := sto.LoadSVID()
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	})

	require.NoError(t, sto.DeleteSVID())

	t.Run("load from same storage instance after delete", func(t *testing.T) {
		actual, err := sto.LoadSVID()
		require.True(t, errors.Is(err, storage.ErrNotCached))
		require.Nil(t, actual)
	})

	sto = fn(t, dir)

	t.Run("load from new storage instance after delete", func(t *testing.T) {
		actual, err := sto.LoadSVID()
		require.True(t, errors.Is(err, storage.ErrNotCached))
		require.Nil(t, actual)
	})
}
