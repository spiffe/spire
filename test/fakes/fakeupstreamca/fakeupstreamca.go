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
	"github.com/spiffe/spire/proto/spire/server/upstreamca"
	"github.com/stretchr/testify/require"
)

var (
	rootKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgt/OIyb8Ossz/5bNk
XtnzFe1T2d0D9quX9Loi1O55b8yhRANCAATDe/2d6z+P095I3dIkocKr4b3zAy+1
qQDuoXqa8i3YOPk5fLib4ORzqD9NJFcrKjI+LLtipQe9yu/eY1K0yhBa
-----END PRIVATE KEY-----
`)
	intKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpsj4nK27QyJgoGgd
dYGswvDV6xdYoxVgn5GPZvM7NxKhRANCAATA/QudaCHS+SIdorglqmSANMf7qZsu
zFoQQSb86LNz+t2Jy/3Ydrwln2AGsii8NKRr9xAVcWR6wR/lVmen81SH
-----END PRIVATE KEY-----
`)
)

type Config struct {
	TrustDomain         string
	UseDeprecatedFields bool
	UseIntermediate     bool
}

type UpstreamCA struct {
	chain      []*x509.Certificate
	upstreamCA *x509svid.UpstreamCA
	config     Config
}

func New(t *testing.T, config Config) *UpstreamCA {
	rootKey, err := pemutil.ParseECPrivateKey(rootKeyPEM)
	require.NoError(t, err, "unable to parse root key")

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "FAKEUPSTREAMCA",
		},
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, template, template, &rootKey.PublicKey, rootKey)
	require.NoError(t, err, "unable to self-sign certificate")

	rootCert, err := x509.ParseCertificate(rootCertDER)
	require.NoError(t, err, "unable to parse self-signed certificate")

	var chain []*x509.Certificate
	cert := rootCert
	key := rootKey

	if config.UseIntermediate {
		template.Subject.CommonName = "FAKEUPSTREAMCA-INT"
		intKey, err := pemutil.ParseECPrivateKey(intKeyPEM)
		require.NoError(t, err, "unable to parse intermediate key")

		intCertDER, err := x509.CreateCertificate(rand.Reader, template, rootCert, &intKey.PublicKey, rootKey)
		require.NoError(t, err, "unable to self intermediate certificate")

		intCert, err := x509.ParseCertificate(intCertDER)
		require.NoError(t, err, "unable to parse intermediate certificate")

		cert = intCert
		key = intKey
		chain = append(chain, intCert)
	}
	chain = append(chain, rootCert)

	upstreamCA := x509svid.NewUpstreamCA(
		x509util.NewMemoryKeypair(cert, key),
		config.TrustDomain,
		x509svid.UpstreamCAOptions{})

	return &UpstreamCA{
		chain:      chain,
		upstreamCA: upstreamCA,
		config:     config,
	}
}

func (m *UpstreamCA) Root() *x509.Certificate {
	return m.chain[len(m.chain)-1]
}

func (m *UpstreamCA) Intermediate() *x509.Certificate {
	if len(m.chain) < 2 {
		return nil
	}
	return m.chain[0]
}

func (m *UpstreamCA) SubmitCSR(ctx context.Context, request *upstreamca.SubmitCSRRequest) (*upstreamca.SubmitCSRResponse, error) {
	cert, err := m.upstreamCA.SignCSR(ctx, request.Csr)
	if err != nil {
		return nil, err
	}

	chain := append([]*x509.Certificate{cert}, m.chain...)

	if m.config.UseDeprecatedFields {
		return &upstreamca.SubmitCSRResponse{
			// Signed CA only
			DEPRECATEDCert: certsDER(chain[0:1]),
			// Chain from intermediates back to the root
			DEPRECATEDUpstreamTrustBundle: certsDER(chain[1:]),
		}, nil
	}

	return &upstreamca.SubmitCSRResponse{
		SignedCertificate: &upstreamca.SignedCertificate{
			// Signed CA + intermediates
			CertChain: certsDER(chain[:len(chain)-1]),
			// Just the root
			Bundle: certsDER(chain[len(chain)-1:]),
		},
	}, nil
}

func certsDER(certs []*x509.Certificate) []byte {
	var out []byte
	for _, cert := range certs {
		out = append(out, cert.Raw...)
	}
	return out
}
