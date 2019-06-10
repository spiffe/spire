package bundle

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/stretchr/testify/require"
)

var (
	testKey, _ = pemutil.ParseSigner([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcyW+Ne33t4e7HVxn
5aWdL02CcurRNixGgu1vVqQzq3+hRANCAASSQSfkTYd3+u8JEMJUw2Pd143QAOKP
24lWY34SXQInPaja544bc67U0dG0YCNozyAtZxIHFjV+t2HGThM8qNYg
-----END PRIVATE KEY-----
`))
)

func createCACertificate(t *testing.T) *x509.Certificate {
	return createCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	})
}

func createCertificate(t *testing.T, tmpl *x509.Certificate) *x509.Certificate {
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, testKey.Public(), testKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

func x5c(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}
