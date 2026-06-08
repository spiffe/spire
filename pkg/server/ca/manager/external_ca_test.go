package manager

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/require"
)

// writeCertFile PEM-encodes cert and writes it to a file in dir, returning the
// path.
func writeCertFile(t *testing.T, dir, name string, certPEM []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, certPEM, 0o600))
	return path
}

// TestNewManagerExternalCAValidation covers the configuration and certificate
// validation performed by NewManager when external X.509 CA mode is enabled.
// These checks run before any PKCS#11 module is loaded, so they can be
// exercised without an HSM.
func TestNewManagerExternalCAValidation(t *testing.T) {
	dir := t.TempDir()

	// A valid root -> intermediate chain.
	root := testca.New(t, testTrustDomain)
	intermediate := root.ChildCA()
	rootPEM := pemutil.EncodeCertificate(root.X509Authorities()[0])
	// A leaf created by the intermediate yields the chain [leaf, intermediateCA];
	// the last element is the intermediate CA certificate itself.
	intermediateChain, _ := intermediate.CreateX509Certificate()
	intermediateCAPEM := pemutil.EncodeCertificate(intermediateChain[len(intermediateChain)-1])

	validRootPath := writeCertFile(t, dir, "root.pem", rootPEM)
	validIntermediatePath := writeCertFile(t, dir, "intermediate.pem", intermediateCAPEM)

	// A self-signed CA not signed by the root (different root).
	otherRoot := testca.New(t, testTrustDomain)
	unsignedIntermediatePEM := pemutil.EncodeCertificate(otherRoot.X509Authorities()[0])
	unsignedIntermediatePath := writeCertFile(t, dir, "unsigned-intermediate.pem", unsignedIntermediatePEM)

	// A non-CA certificate signed by the root.
	nonCACerts, _ := root.CreateX509Certificate()
	nonCAPEM := pemutil.EncodeCertificate(nonCACerts[0])
	nonCAPath := writeCertFile(t, dir, "non-ca.pem", nonCAPEM)

	baseConfig := func(t *testing.T) Config {
		mt := setupTest(t)
		c := mt.selfSignedConfig()
		c.UseExternalX509CA = true
		c.RootCertPath = validRootPath
		c.IntermediateCertPath = validIntermediatePath
		c.PKCS11URI = "pkcs11:module-path=/does/not/matter;token=SPIRE;pin-value=1234"
		c.PKCS11SigningKey = "pkcs11:object=intermediate-ca-key"
		return c
	}

	t.Run("missing root_cert_file_path", func(t *testing.T) {
		c := baseConfig(t)
		c.RootCertPath = ""
		_, err := NewManager(context.Background(), c)
		require.EqualError(t, err, "external CA mode requires root_cert_file_path to be configured")
	})

	t.Run("missing cert_file_path", func(t *testing.T) {
		c := baseConfig(t)
		c.IntermediateCertPath = ""
		_, err := NewManager(context.Background(), c)
		require.EqualError(t, err, "external CA mode requires cert_file_path to be configured")
	})

	t.Run("missing pkcs11_uri", func(t *testing.T) {
		c := baseConfig(t)
		c.PKCS11URI = ""
		_, err := NewManager(context.Background(), c)
		require.EqualError(t, err, "external CA mode requires pkcs11_uri to be configured")
	})

	t.Run("missing pkcs11_object", func(t *testing.T) {
		c := baseConfig(t)
		c.PKCS11SigningKey = ""
		_, err := NewManager(context.Background(), c)
		require.EqualError(t, err, "external CA mode requires pkcs11_object to be configured")
	})

	t.Run("root certificate file does not exist", func(t *testing.T) {
		c := baseConfig(t)
		c.RootCertPath = filepath.Join(dir, "missing-root.pem")
		_, err := NewManager(context.Background(), c)
		require.ErrorContains(t, err, "failed to load root CA certificate")
	})

	t.Run("intermediate certificate file does not exist", func(t *testing.T) {
		c := baseConfig(t)
		c.IntermediateCertPath = filepath.Join(dir, "missing-intermediate.pem")
		_, err := NewManager(context.Background(), c)
		require.ErrorContains(t, err, "failed to load intermediate CA certificate")
	})

	t.Run("intermediate not signed by root", func(t *testing.T) {
		c := baseConfig(t)
		c.IntermediateCertPath = unsignedIntermediatePath
		_, err := NewManager(context.Background(), c)
		require.ErrorContains(t, err, "intermediate CA certificate is not signed by root CA")
	})

	t.Run("intermediate is not a CA certificate", func(t *testing.T) {
		c := baseConfig(t)
		c.IntermediateCertPath = nonCAPath
		_, err := NewManager(context.Background(), c)
		require.ErrorContains(t, err, "intermediate certificate is not a CA certificate")
	})

	t.Run("valid chain proceeds to PKCS11 initialization", func(t *testing.T) {
		// With a valid configuration and chain, validation passes and the
		// manager attempts to load the PKCS#11 module. Since the module path is
		// bogus, it fails at PKCS#11 initialization rather than at any of the
		// validation checks above, proving the validation gate was cleared.
		c := baseConfig(t)
		_, err := NewManager(context.Background(), c)
		require.ErrorContains(t, err, "PKCS#11")
	})
}

func TestPublicKeysEqual(t *testing.T) {
	root := testca.New(t, testTrustDomain)
	other := testca.New(t, testTrustDomain)

	rootKey := root.X509Authorities()[0].PublicKey
	otherKey := other.X509Authorities()[0].PublicKey

	require.True(t, publicKeysEqual(rootKey, rootKey))
	require.False(t, publicKeysEqual(rootKey, otherKey))
	require.False(t, publicKeysEqual(rootKey, nil))
}
