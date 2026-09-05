package client

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/stretchr/testify/require"
)

func TestLoadBootstrapX509Authorities(t *testing.T) {
	cert := createCACertificate(t, "bootstrap")
	td := trustDomain

	t.Run("pem", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bundle.pem")
		require.NoError(t, os.WriteFile(path, pemutil.EncodeCertificate(cert), 0600))

		got, err := loadBootstrapX509Authorities(path, BootstrapBundleFormatPEM, td)
		require.NoError(t, err)
		require.Equal(t, cert.Raw, got[0].Raw)
	})

	t.Run("spiffe", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bundle.json")
		bundle := spiffebundle.FromX509Authorities(td, []*x509.Certificate{cert})
		data, err := bundleutil.Marshal(bundle)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, data, 0600))

		got, err := loadBootstrapX509Authorities(path, BootstrapBundleFormatSPIFFE, td)
		require.NoError(t, err)
		require.Equal(t, cert.Raw, got[0].Raw)
	})

	t.Run("defaults to pem", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bundle.pem")
		require.NoError(t, os.WriteFile(path, pemutil.EncodeCertificate(cert), 0600))

		got, err := loadBootstrapX509Authorities(path, "", td)
		require.NoError(t, err)
		require.Equal(t, cert.Raw, got[0].Raw)
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := loadBootstrapX509Authorities(filepath.Join(t.TempDir(), "missing.pem"), BootstrapBundleFormatPEM, td)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to load bootstrap bundle")
	})

	t.Run("unknown format", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bundle.pem")
		require.NoError(t, os.WriteFile(path, pemutil.EncodeCertificate(cert), 0600))

		_, err := loadBootstrapX509Authorities(path, "der", td)
		require.EqualError(t, err, `unknown bootstrap bundle format "der"`)
	})
}
