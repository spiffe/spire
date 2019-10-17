package spiretest

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/stretchr/testify/require"
)

var (
	EC256Key, _ = pemutil.ParseSigner([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcyW+Ne33t4e7HVxn
5aWdL02CcurRNixGgu1vVqQzq3+hRANCAASSQSfkTYd3+u8JEMJUw2Pd143QAOKP
24lWY34SXQInPaja544bc67U0dG0YCNozyAtZxIHFjV+t2HGThM8qNYg
-----END PRIVATE KEY-----
`))
	DefaultKey = EC256Key
)

func SelfSignCertificate(tb testing.TB, tmpl *x509.Certificate) (*x509.Certificate, crypto.Signer) {
	return SelfSignCertificateWithKey(tb, tmpl, DefaultKey), DefaultKey
}

func SelfSignCertificateWithKey(tb testing.TB, tmpl *x509.Certificate, key crypto.Signer) *x509.Certificate {
	return CreateCertificate(tb, tmpl, tmpl, key.Public(), key)
}

func CreateCertificate(tb testing.TB, tmpl, parent *x509.Certificate, pub, priv interface{}) *x509.Certificate {
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	require.NoError(tb, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(tb, err)
	return cert
}
