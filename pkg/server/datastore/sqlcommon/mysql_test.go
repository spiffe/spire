package sqlcommon

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
)

func TestHasTLSConfig(t *testing.T) {
	require.False(t, HasTLSConfig(&Configuration{}))
	require.True(t, HasTLSConfig(&Configuration{RootCAPath: "/ca.pem"}))
	require.True(t, HasTLSConfig(&Configuration{
		ClientCertPath: "/cert.pem",
		ClientKeyPath:  "/key.pem",
	}))
	// a client cert without its key does not count
	require.False(t, HasTLSConfig(&Configuration{ClientCertPath: "/cert.pem"}))
}

func TestConfigureMySQLConnectionNoTLS(t *testing.T) {
	cfg := &Configuration{
		ConnectionString: "user:pass@tcp(localhost:3306)/spire?parseTime=true",
		DBTypeConfig:     &DBTypeConfig{DatabaseType: MySQL},
	}
	mysqlConfig, err := ConfigureMySQLConnection(cfg, false)
	require.NoError(t, err)
	// with no custom TLS material configured, the driver TLS config is untouched
	require.Empty(t, mysqlConfig.TLSConfig)
}

func TestConfigureMySQLConnectionRegistersTLS(t *testing.T) {
	// generate a throwaway CA PEM so RootCAPath parses.
	caPath := writeTestRootCA(t)

	cfg := &Configuration{
		ConnectionString: "user:pass@tcp(localhost:3306)/spire?parseTime=true",
		RootCAPath:       caPath,
		DBTypeConfig:     &DBTypeConfig{DatabaseType: MySQL},
	}
	mysqlConfig, err := ConfigureMySQLConnection(cfg, false)
	require.NoError(t, err)

	// the driver config must point at the custom TLS config, and that name must
	// resolve to a registered tls.Config in the driver's registry.
	require.Equal(t, TLSConfigName, mysqlConfig.TLSConfig)
	_, err = mysql.ParseDSN(mysqlConfig.FormatDSN())
	require.NoError(t, err, "formatted DSN with custom TLS must be parseable")
}

func TestConfigureMySQLConnectionBadRootCA(t *testing.T) {
	cfg := &Configuration{
		ConnectionString: "user:pass@tcp(localhost:3306)/spire?parseTime=true",
		RootCAPath:       "/does/not/exist.pem",
		DBTypeConfig:     &DBTypeConfig{DatabaseType: MySQL},
	}
	_, err := ConfigureMySQLConnection(cfg, false)
	require.ErrorContains(t, err, "cannot find Root CA defined in root_ca_path")
}

func writeTestRootCA(t *testing.T) string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "root-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
	return path
}
