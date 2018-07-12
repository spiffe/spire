package fakeupstreamca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/server/upstreamca"
	"github.com/stretchr/testify/require"
)

var (
	keyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgt/OIyb8Ossz/5bNk
XtnzFe1T2d0D9quX9Loi1O55b8yhRANCAATDe/2d6z+P095I3dIkocKr4b3zAy+1
qQDuoXqa8i3YOPk5fLib4ORzqD9NJFcrKjI+LLtipQe9yu/eY1K0yhBa
-----END PRIVATE KEY-----
`)
)

type UpstreamCA struct {
	cert       *x509.Certificate
	upstreamCA *x509svid.UpstreamCA
}

func New(t *testing.T, trustDomain string) *UpstreamCA {
	key, err := pemutil.ParseECPrivateKey(keyPEM)
	require.NoError(t, err, "unable to parse key")

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "FAKEUPSTREAMCA",
		},
		NotAfter: time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err, "unable to self-sign certificate")

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err, "unable to parse self-signed certificate")

	upstreamCA := x509svid.NewUpstreamCA(
		x509util.NewMemoryKeypair(cert, key),
		trustDomain,
		x509svid.UpstreamCAOptions{})

	return &UpstreamCA{
		cert:       cert,
		upstreamCA: upstreamCA,
	}
}

func (m *UpstreamCA) Cert() *x509.Certificate {
	return m.cert
}

func (m *UpstreamCA) SubmitCSR(ctx context.Context, request *upstreamca.SubmitCSRRequest) (*upstreamca.SubmitCSRResponse, error) {
	cert, err := m.upstreamCA.SignCSR(ctx, request.Csr)
	if err != nil {
		return nil, err
	}

	return &upstreamca.SubmitCSRResponse{
		Cert:                cert.Raw,
		UpstreamTrustBundle: m.cert.Raw,
	}, nil
}
