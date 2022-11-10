package gcpcas

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"cloud.google.com/go/security/privateca/apiv1/privatecapb"
	"github.com/spiffe/spire/pkg/common/pemutil"
	commonutil "github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestInvalidConfigs(t *testing.T) {
	// ctx := context.Background()
	for i, config := range []string{
		// Missing project_name
		`root_cert_spec {
			region_name = "us-central1"
			ca_pool = "test-pool"
			label_key = "proj-signer"
			label_value = "true"
		    }`,
		// Empty project_name
		`root_cert_spec {
			project_name = ""
			region_name = "us-central1"
			ca_pool = "test-pool"
			label_key = "proj-signer"
			label_value = "true"
		    }`,
		// Missing region name
		`root_cert_spec {
			project_name = "proj1"
			ca_pool = "test-pool"
			label_key = "proj-signer"
			label_value = "true"
		    }`,
		// Empty region name
		`root_cert_spec {
			project_name = "proj1"
			region_name = ""
			ca_pool = "test-pool"
			label_key = "proj-signer"
			label_value = "true"
		    }`,
		// Missing label key
		`root_cert_spec {
			project_name = "proj1"
			region_name = "us-central1"
			ca_pool = "test-pool"
			label_value = "true"
		    }`,
		// Empty label key
		`root_cert_spec {
			project_name = "proj1"
			region_name = "us-central1"
			ca_pool = "test-pool"
			label_key = ""
			label_value = "true"
		    }`,
		// Missing label value
		`root_cert_spec {
			project_name = "proj1"
			region_name = "us-central1"
			ca_pool = "test-pool"
			label_key = "proj-signer"
		    }`,
		// Empty label value
		`root_cert_spec {
			project_name = "proj1"
			region_name = "us-central1"
			ca_pool = "test-pool"
			label_key = "proj-signer"
			label_value = ""
		    }`,
	} {
		var err error
		plugintest.Load(t, BuiltIn(), new(upstreamauthority.V1),
			plugintest.Configure(config),
			plugintest.CaptureConfigureError(&err))
		t.Logf("\ntestcase[%d] and err:%+v\n", i, err)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	}
}

func TestGcpCAS(t *testing.T) {
	p := New()
	p.hook.getClient = func(ctxt context.Context) (CAClient, error) {
		// Scenario:
		//   We mock client's LoadCertificateAuthorities() to return in the following order:
		//      * caZ is an intermediate CA which is signed by externalCAY
		//      * caX is a root CA that is in GCP CAS with the second oldest expiry (T + 2)
		//      * caM is a root CA that is in GCP CAS with the earliest expiry (T + 1) but it is DISABLED
		//   Everything except caM are in ENABLED state
		//   Also note that the above is not ordered by expiry time
		// Expectation:
		//   * caX should be selected for signing
		//   * root trust bundle should have { caX, externalcaY }. It should
		//     neither have DISABLED caM nor intermediate caZ
		caX, pkeyCAx, err := generateCert(t, "caX", nil, nil, 2, testkey.NewEC384)
		require.NoError(t, err)
		require.NotNil(t, pkeyCAx)
		require.NotNil(t, caX)

		caY, pkeyCAy, err := generateCert(t, "externalcaY", nil, nil, 3, testkey.NewEC384)
		require.NoError(t, err)
		require.NotNil(t, pkeyCAy)
		require.NotNil(t, caY)

		caZ, _, err := generateCert(t, "caZ", caY, pkeyCAy, 3, testkey.NewEC384)
		require.NoError(t, err)
		require.NotNil(t, caZ)

		caM, _, err := generateCert(t, "caM", nil, nil, 1, testkey.NewEC384)
		require.NoError(t, err)
		require.NotNil(t, pkeyCAx)
		require.NotNil(t, caX)

		// Note: fakeClient.LoadCertificateAuthority() will automatically
		// mark the last CA (i.e. caM) as DISABLED
		// The rest (caX, caZ, caY) will be marked as ENABLED
		cas := [][]*x509.Certificate{{caX}, {caZ, caY}, {caM}}
		return &fakeClient{cas, t, &pkeyCAx}, nil
	}

	upplugin := new(upstreamauthority.V1)
	plugintest.Load(t, builtin(p), upplugin, plugintest.Configure(`
		root_cert_spec {
			project_name = "proj1"
			region_name = "us-central1"
			ca_pool = "test-pool"
			label_key = "proj-signer"
			label_value = "true"
		}
    `))

	priv := testkey.NewEC384(t)
	csr, err := commonutil.MakeCSRWithoutURISAN(priv)
	require.NoError(t, err)

	ctx := context.Background()
	x509CA, x509Authorities, stream, err := upplugin.MintX509CA(ctx, csr, 30*time.Second)
	require.NoError(t, err)
	require.NotNil(t, stream)

	require.NotNil(t, x509Authorities)
	// Confirm that we don't have unexpected CAs
	require.Equal(t, 2, len(x509Authorities))
	require.Equal(t, "caX", x509Authorities[0].Subject.CommonName)
	require.Equal(t, "caX", x509Authorities[0].Issuer.CommonName)
	// We intentionally return the root externalcaY rather than intermediate caZ
	require.Equal(t, "externalcaY", x509Authorities[1].Subject.CommonName)
	require.Equal(t, "externalcaY", x509Authorities[1].Issuer.CommonName)

	require.NotNil(t, x509CA)
	require.Equal(t, 1, len(x509CA))

	require.Equal(t, "caX", x509CA[0].Issuer.CommonName)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(x509Authorities[0])
	rootPool.AddCert(x509Authorities[1])
	var opt x509.VerifyOptions
	opt.Roots = rootPool
	res, err := x509CA[0].Verify(opt)
	require.NoError(t, err)
	require.NotNil(t, res)
}

func generateCert(t *testing.T, cn string, issuer *x509.Certificate, issuerKey crypto.PrivateKey, ttlInHours int, keyfn func(testing.TB) *ecdsa.PrivateKey) (*x509.Certificate, crypto.PrivateKey, error) {
	priv := keyfn(t)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Duration(ttlInHours) * time.Hour),

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
	require.Equal(client.t, req.IssuingCertificateAuthorityId, client.mockX509CAs[0][0].Subject.CommonName)

	// Mimic GCP GCA signing
	// By first issuing a x509 cert and then converting it into GCP cert format
	commonName := req.Certificate.GetConfig().GetSubjectConfig().GetSubject().GetCommonName()
	x509ca, _, err := generateCert(client.t, commonName, client.mockX509CAs[0][0],
		*client.privKeyOfEarliestCA, 1 /* TTL */, testkey.NewEC256)
	require.NoError(client.t, err)
	require.NotNil(client.t, x509ca)

	ca := new(privatecapb.Certificate)
	ca.Name = commonName
	ca.PemCertificate = string(pemutil.EncodeCertificate(x509ca))
	ca.PemCertificateChain = []string{}
	for _, caentry := range client.mockX509CAs[0] {
		ca.PemCertificateChain = append(ca.PemCertificateChain, string(pemutil.EncodeCertificate(caentry)))
	}
	return ca, nil
}

func (client *fakeClient) LoadCertificateAuthorities(ctx context.Context, spec CertificateAuthoritySpec) ([]*privatecapb.CertificateAuthority, error) {
	var allCerts []*privatecapb.CertificateAuthority
	for _, x509CA := range client.mockX509CAs {
		ca := new(privatecapb.CertificateAuthority)
		ca.Name = x509CA[0].Subject.CommonName
		ca.State = privatecapb.CertificateAuthority_ENABLED
		ca.PemCaCertificates = []string{}
		for _, caentry := range x509CA {
			ca.PemCaCertificates = append(ca.PemCaCertificates, string(pemutil.EncodeCertificate(caentry)))
		}
		allCerts = append(allCerts, ca)
	}
	// Intentionally mimic the last one as DISABLED
	allCerts[len(allCerts)-1].State = privatecapb.CertificateAuthority_DISABLED
	return allCerts, nil
}
