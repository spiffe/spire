package gcpcas

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/pemutil"
	commonutil "github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
)

func generateCert(cn string, issuer *x509.Certificate, issuerKey crypto.PrivateKey) (*x509.Certificate, crypto.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if issuer == nil {
		issuer = template
		issuerKey = priv
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, issuer, priv.Public(), issuerKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

type fakeClient struct { // implements CAClient interface
	// Outer slice has list of CAs. Inner slice for each CA is the rest of the CA chain
	mockX509CAs [][]*x509.Certificate
	t           *testing.T
	// This is the private key corresponding to mockX509CAs[0][0]
	privKeyOfEarliestCA *crypto.PrivateKey
}

func (client *fakeClient) CreateCertificate(ctx context.Context, req *privatecapb.CreateCertificateRequest) (*privatecapb.Certificate, error) {
	// Confirm that we were called with a request to sign using
	// the very first CA from the CA List ( i.e. issuance order )
	require.Equal(client.t, req.Parent, client.mockX509CAs[0][0].Subject.CommonName)

	// Mimic GCP GCA signing
	// By first issuing a x509 cert and then converting it into GCP cert format
	commonName := req.Certificate.GetConfig().GetSubjectConfig().GetCommonName()
	x509ca, _, err := generateCert(commonName, client.mockX509CAs[0][0], *client.privKeyOfEarliestCA)
	require.NoError(client.t, err)
	require.NotNil(client.t, x509ca)

	ca := new(privatecapb.Certificate)
	ca.Name = commonName
	ca.PemCertificate = string(pemutil.EncodeCertificate(x509ca))
	ca.PemCertificateChain = make([]string, 0)
	for _, caentry := range client.mockX509CAs[0] {
		ca.PemCertificateChain = append(ca.PemCertificateChain, string(pemutil.EncodeCertificate(caentry)))
	}
	return ca, nil
}

func (client *fakeClient) LoadCertificateAuthorities(ctx context.Context, spec CertificateAuthoritySpec) ([]*privatecapb.CertificateAuthority, error) {
	allCerts := make([]*privatecapb.CertificateAuthority, 0)
	for _, x509CA := range client.mockX509CAs {
		ca := new(privatecapb.CertificateAuthority)
		ca.Name = x509CA[0].Subject.CommonName
		ca.PemCaCertificates = make([]string, 0)
		for _, caentry := range x509CA {
			ca.PemCaCertificates = append(ca.PemCaCertificates, string(pemutil.EncodeCertificate(caentry)))
		}
		allCerts = append(allCerts, ca)
	}
	return allCerts, nil
}

func TestGcpCAS(t *testing.T) {
	p := New()
	p.hook.getClient = func(ctxt context.Context) (CAClient, error) {
		// Scenario:
		// caX is a root CA that is in GCP CAS
		// caZ is an intermediate CA which is signed by externalCAY
		caX, pkeyCAx, err := generateCert("caX", nil, nil)
		require.NoError(t, err)
		require.NotNil(t, pkeyCAx)
		require.NotNil(t, caX)

		caY, pkeyCAy, err := generateCert("externalcaY", nil, nil)
		require.NoError(t, err)
		require.NotNil(t, pkeyCAy)
		require.NotNil(t, caY)

		caZ, _, err := generateCert("caZ", caY, pkeyCAy)
		require.NoError(t, err)
		require.NotNil(t, caZ)
		cas := [][]*x509.Certificate{{caX}, {caZ, caY}}
		return &fakeClient{cas, t, &pkeyCAx}, nil
	}
	var upplugin upstreamauthority.Plugin
	spiretest.LoadPlugin(t, builtin(p), &upplugin)

	ctx := context.Background()
	_, err := p.Configure(context.Background(), &plugin.ConfigureRequest{Configuration: `
    root_cert_spec {
        project_name = "proj1"
        region_name = "us-central1"
        label_key = "proj-signer"
        label_value = "true"
    }

    trust_bundle_cert_spec = [
        {
            project_name = "proj1"
            region_name = "us-central1"
            label_key = "somelable"
            label_value = "somevalue"
        }
    ]
    `})
	require.NoError(t, err)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csr, err := commonutil.MakeCSRWithoutURISAN(priv)
	require.NoError(t, err)

	resp, err := p.mintX509CA(ctx, csr, 30)
	require.NoError(t, err)
	require.NotNil(t, resp)

	respCaChain, err := x509util.RawCertsToCertificates(resp.X509CaChain)
	require.NoError(t, err)
	require.NotNil(t, respCaChain)
	require.Equal(t, respCaChain[0].Issuer.CommonName, "caX")

	respRootChain, err := x509util.RawCertsToCertificates(resp.UpstreamX509Roots)
	require.NoError(t, err)
	require.NotNil(t, respRootChain)
	require.Equal(t, 2, len(respRootChain))
	// Root chains should have both the CAs
	require.Equal(t, respRootChain[0].Subject.CommonName, "caX")
	require.Equal(t, respRootChain[0].Issuer.CommonName, "caX")
	// We intentionally return caZ
	require.Equal(t, respRootChain[1].Subject.CommonName, "caZ")
	require.Equal(t, respRootChain[1].Issuer.CommonName, "externalcaY")
}
