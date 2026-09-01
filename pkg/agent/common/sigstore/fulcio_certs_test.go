package sigstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	sigstoreroot "github.com/sigstore/sigstore-go/pkg/root"
	"github.com/stretchr/testify/require"
)

type fakeCertificateAuthority struct{}

func (fakeCertificateAuthority) Verify(*x509.Certificate, time.Time) ([][]*x509.Certificate, error) {
	return nil, nil
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

	rootsSubjects := roots.Subjects()
	require.Len(t, rootsSubjects, 1)
	require.Equal(t, rootCert.RawSubject, rootsSubjects[0])

	intermediateSubjects := intermediates.Subjects()
	require.Len(t, intermediateSubjects, 1)
	require.Equal(t, intermediateCert.RawSubject, intermediateSubjects[0])
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
