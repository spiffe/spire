package run

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/pkg/common/log"
	"github.com/stretchr/testify/require"
)

// TestParseConfigExternalCA verifies the experimental external_ca / pkcs11 HCL
// block is decoded into the config struct.
func TestParseConfigExternalCA(t *testing.T) {
	hclConfig := `
server {
	bind_address = "127.0.0.1"
	bind_port = "8081"
	trust_domain = "example.org"
	data_dir = "."

	experimental {
		external_ca {
			enabled = true
			root_cert_file_path = "/opt/spire/certs/root-cert.pem"
			cert_file_path = "/opt/spire/certs/intermediate-cert.pem"
			pkcs11 {
				pkcs11_uri = "pkcs11:module-path=/usr/lib/softhsm/libsofthsm2.so;token=SPIRE;pin-value=1234"
				pkcs11_object = "pkcs11:object=intermediate-ca-key"
			}
		}
	}
}
plugins {}
`
	dir := t.TempDir()
	confPath := filepath.Join(dir, "server.conf")
	require.NoError(t, os.WriteFile(confPath, []byte(hclConfig), 0o600))

	c, err := ParseFile(confPath, false)
	require.NoError(t, err)

	extCA := c.Server.Experimental.ExternalCA
	require.NotNil(t, extCA)
	require.True(t, extCA.Enabled)
	require.Equal(t, "/opt/spire/certs/root-cert.pem", extCA.RootCertFilePath)
	require.Equal(t, "/opt/spire/certs/intermediate-cert.pem", extCA.CertFilePath)
	require.NotNil(t, extCA.PKCS11)
	require.Equal(t, "pkcs11:module-path=/usr/lib/softhsm/libsofthsm2.so;token=SPIRE;pin-value=1234", extCA.PKCS11.Pkcs11URI)
	require.Equal(t, "pkcs11:object=intermediate-ca-key", extCA.PKCS11.Pkcs11Object)
}

// TestNewServerConfigExternalCA verifies the external_ca config is plumbed into
// the server.Config when enabled, and ignored when disabled.
func TestNewServerConfigExternalCA(t *testing.T) {
	logOptions := []log.Option{}

	t.Run("enabled", func(t *testing.T) {
		c := defaultValidConfig()
		c.Server.Experimental.ExternalCA = &externalCAConfig{
			Enabled:          true,
			RootCertFilePath: "/root.pem",
			CertFilePath:     "/intermediate.pem",
			PKCS11: &pkcs11Config{
				Pkcs11URI:    "pkcs11:token=SPIRE;pin-value=1234",
				Pkcs11Object: "pkcs11:object=intermediate-ca-key",
			},
		}

		sc, err := NewServerConfig(c, logOptions, false)
		require.NoError(t, err)
		require.True(t, sc.ExternalCA.Enabled)
		require.Equal(t, "/root.pem", sc.ExternalCA.RootCertFilePath)
		require.Equal(t, "/intermediate.pem", sc.ExternalCA.CertFilePath)
		require.NotNil(t, sc.ExternalCA.PKCS11)
		require.Equal(t, "pkcs11:token=SPIRE;pin-value=1234", sc.ExternalCA.PKCS11.PKCS11URI)
		require.Equal(t, "pkcs11:object=intermediate-ca-key", sc.ExternalCA.PKCS11.PKCS11Object)
	})

	t.Run("disabled leaves external CA unset", func(t *testing.T) {
		c := defaultValidConfig()
		c.Server.Experimental.ExternalCA = &externalCAConfig{Enabled: false}

		sc, err := NewServerConfig(c, logOptions, false)
		require.NoError(t, err)
		require.False(t, sc.ExternalCA.Enabled)
		require.Nil(t, sc.ExternalCA.PKCS11)
	})

	t.Run("absent leaves external CA unset", func(t *testing.T) {
		c := defaultValidConfig()

		sc, err := NewServerConfig(c, logOptions, false)
		require.NoError(t, err)
		require.False(t, sc.ExternalCA.Enabled)
		require.Nil(t, sc.ExternalCA.PKCS11)
	})
}
