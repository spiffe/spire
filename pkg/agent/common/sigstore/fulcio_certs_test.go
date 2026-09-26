package sigstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	sigstoreroot "github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/stretchr/testify/require"
)

type fakeCertificateAuthority struct{}

func (fakeCertificateAuthority) Verify(*x509.Certificate, time.Time) ([][]*x509.Certificate, error) {
	return nil, nil
}

func TestTufOptions(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		t.Setenv(tufRootEnv, "")
		t.Setenv(sigstoreNoCacheEnv, "")
		t.Setenv(sigstoreRootFileEnv, "")

		opts, err := tufOptions()
		require.NoError(t, err)
		require.False(t, opts.DisableLocalCache)
		require.True(t, filepath.IsAbs(opts.CachePath))
		require.Contains(t, opts.CachePath, filepath.Join(".sigstore", "root"))
		require.Equal(t, tuf.DefaultMirror, opts.RepositoryBaseURL)
	})

	t.Run("custom TUF root", func(t *testing.T) {
		t.Setenv(tufRootEnv, "/var/lib/spire/tuf")
		t.Setenv(sigstoreNoCacheEnv, "")

		opts, err := tufOptions()
		require.NoError(t, err)
		require.Equal(t, "/var/lib/spire/tuf", opts.CachePath)
	})

	t.Run("disable local cache", func(t *testing.T) {
		t.Setenv(tufRootEnv, "")
		t.Setenv(sigstoreNoCacheEnv, "true")

		opts, err := tufOptions()
		require.NoError(t, err)
		require.True(t, opts.DisableLocalCache)
	})

	t.Run("invalid no cache value", func(t *testing.T) {
		t.Setenv(sigstoreNoCacheEnv, "not-a-bool")

		opts, err := tufOptions()
		require.NoError(t, err)
		require.False(t, opts.DisableLocalCache)
	})

	t.Run("remote mirror from remote.json", func(t *testing.T) {
		cacheRoot := t.TempDir()
		t.Setenv(tufRootEnv, cacheRoot)
		t.Setenv(sigstoreRootFileEnv, "")

		require.NoError(t, os.WriteFile(
			filepath.Join(cacheRoot, remoteCacheFile),
			[]byte(`{"mirror":"https://private-tuf.example.com"}`),
			0o600,
		))

		opts, err := tufOptions()
		require.NoError(t, err)
		require.Equal(t, "https://private-tuf.example.com", opts.RepositoryBaseURL)
	})

	t.Run("missing remote.json uses default mirror", func(t *testing.T) {
		cacheRoot := t.TempDir()
		t.Setenv(tufRootEnv, cacheRoot)

		opts, err := tufOptions()
		require.NoError(t, err)
		require.Equal(t, tuf.DefaultMirror, opts.RepositoryBaseURL)
	})

	t.Run("invalid remote.json", func(t *testing.T) {
		cacheRoot := t.TempDir()
		t.Setenv(tufRootEnv, cacheRoot)

		require.NoError(t, os.WriteFile(
			filepath.Join(cacheRoot, remoteCacheFile),
			[]byte(`not-json`),
			0o600,
		))

		_, err := tufOptions()
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing remote.json")
	})

	t.Run("custom mirror loads root from cache root", func(t *testing.T) {
		cacheRoot := t.TempDir()
		t.Setenv(tufRootEnv, cacheRoot)
		t.Setenv(sigstoreRootFileEnv, "")

		rootBytes := []byte(`{"root":"metadata"}`)
		require.NoError(t, os.WriteFile(filepath.Join(cacheRoot, remoteCacheFile), []byte(`{"mirror":"https://private-tuf.example.com"}`), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(cacheRoot, tufRootFile), rootBytes, 0o600))

		opts, err := tufOptions()
		require.NoError(t, err)
		require.Equal(t, rootBytes, opts.Root)
	})

	t.Run("custom mirror loads root from SIGSTORE_ROOT_FILE", func(t *testing.T) {
		cacheRoot := t.TempDir()
		rootFile := filepath.Join(t.TempDir(), "custom-root.json")
		rootBytes := []byte(`{"root":"from-env"}`)

		t.Setenv(tufRootEnv, cacheRoot)
		t.Setenv(sigstoreRootFileEnv, rootFile)
		require.NoError(t, os.WriteFile(rootFile, rootBytes, 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(cacheRoot, remoteCacheFile), []byte(`{"mirror":"https://private-tuf.example.com"}`), 0o600))

		opts, err := tufOptions()
		require.NoError(t, err)
		require.Equal(t, rootBytes, opts.Root)
	})
}

func TestCertPoolsFromCertificateAuthorities(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rootCert := createTestCertificate(t, rootKey, rootKey, true)
	intermediateCert := createTestCertificate(t, intermediateKey, rootKey, false)

	cas := []sigstoreroot.CertificateAuthority{
		&sigstoreroot.FulcioCertificateAuthority{
			Root:          rootCert,
			Intermediates: []*x509.Certificate{intermediateCert},
		},
	}

	roots, intermediates, err := certPoolsFromCertificateAuthorities(cas)
	require.NoError(t, err)
	require.NotNil(t, roots)
	require.NotNil(t, intermediates)

	expectedRoots := x509.NewCertPool()
	expectedRoots.AddCert(rootCert)
	require.True(t, roots.Equal(expectedRoots))

	expectedIntermediates := x509.NewCertPool()
	expectedIntermediates.AddCert(intermediateCert)
	require.True(t, intermediates.Equal(expectedIntermediates))
}

func TestCertPoolsFromCertificateAuthoritiesErrors(t *testing.T) {
	t.Run("no certificate authorities", func(t *testing.T) {
		_, _, err := certPoolsFromCertificateAuthorities(nil)
		require.Error(t, err)
	})

	t.Run("unexpected certificate authority type", func(t *testing.T) {
		_, _, err := certPoolsFromCertificateAuthorities([]sigstoreroot.CertificateAuthority{
			&fakeCertificateAuthority{},
		})
		require.Error(t, err)
	})

	t.Run("missing root certificate", func(t *testing.T) {
		_, _, err := certPoolsFromCertificateAuthorities([]sigstoreroot.CertificateAuthority{
			&sigstoreroot.FulcioCertificateAuthority{},
		})
		require.Error(t, err)
	})
}

func createTestCertificate(t *testing.T, subjectKey, issuerKey *ecdsa.PrivateKey, selfSigned bool) *x509.Certificate {
	t.Helper()

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "test-cert",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	issuer := template
	if !selfSigned {
		issuer = &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "test-root",
			},
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, issuer, &subjectKey.PublicKey, issuerKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}
