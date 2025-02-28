package x509pop

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
)

var (
	testRSAKey   = testkey.MustRSA2048()
	testECDSAKey = testkey.MustEC256()
)

func TestChallengeResponse(t *testing.T) {
	require := require.New(t)

	// load up RSA key and create a self-signed certificate over the public key
	rsaPrivateKey := testRSAKey
	rsaPublicKey := &rsaPrivateKey.PublicKey
	rsaCert, err := createCertificate(rsaPrivateKey, rsaPublicKey)
	require.NoError(err)

	// verify the RSA challenge/response flow
	rsaChallenge, err := GenerateChallenge(rsaCert)
	require.NoError(err)
	rsaResponse, err := CalculateResponse(rsaPrivateKey, rsaChallenge)
	require.NoError(err)
	err = VerifyChallengeResponse(rsaPublicKey, rsaChallenge, rsaResponse)
	require.NoError(err)

	// load up ECDSA key and create a self-signed certificate over the public key
	ecdsaPrivateKey := testECDSAKey
	ecdsaPublicKey := &ecdsaPrivateKey.PublicKey
	ecdsaCert, err := createCertificate(ecdsaPrivateKey, ecdsaPublicKey)
	require.NoError(err)

	// verify the ECDSA challenge/response flow
	ecdsaChallenge, err := GenerateChallenge(ecdsaCert)
	require.NoError(err)
	ecdsaResponse, err := CalculateResponse(ecdsaPrivateKey, ecdsaChallenge)
	require.NoError(err)
	err = VerifyChallengeResponse(ecdsaPublicKey, ecdsaChallenge, ecdsaResponse)
	require.NoError(err)

	// assert various misconfigurations fail
	_, err = CalculateResponse(rsaPrivateKey, ecdsaChallenge)
	require.EqualError(err, "expecting RSA challenge")
	_, err = CalculateResponse(ecdsaPrivateKey, rsaChallenge)
	require.EqualError(err, "expecting ECDSA challenge")
	err = VerifyChallengeResponse(rsaPublicKey, ecdsaChallenge, rsaResponse)
	require.EqualError(err, "expecting RSA challenge")
	err = VerifyChallengeResponse(rsaPublicKey, rsaChallenge, ecdsaResponse)
	require.EqualError(err, "expecting RSA response")
	err = VerifyChallengeResponse(ecdsaPublicKey, rsaChallenge, ecdsaResponse)
	require.EqualError(err, "expecting ECDSA challenge")
	err = VerifyChallengeResponse(ecdsaPublicKey, ecdsaChallenge, rsaResponse)
	require.EqualError(err, "expecting ECDSA response")

	// mutate the signatures and assert verification fails
	rsaResponse.RSASignature.Signature[0]++
	err = VerifyChallengeResponse(rsaPublicKey, rsaChallenge, rsaResponse)
	require.EqualError(err, "RSA signature verify failed")
	ecdsaResponse.ECDSASignature.R[0]++
	err = VerifyChallengeResponse(ecdsaPublicKey, ecdsaChallenge, ecdsaResponse)
	require.EqualError(err, "ECDSA signature verify failed")

	// assert a challenge cannot be generated for an inappropriate certificate
	badCert, err := createBadCertificate(rsaPrivateKey, rsaPublicKey)
	require.NoError(err)
	_, err = GenerateChallenge(badCert)
	require.EqualError(err, "certificate not intended for digital signature use")
}

func createCertificate(privateKey, publicKey any) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certBytes)
}

// createBadCertificate creates a certificate that is not appropriate to use
// for signature-based challenge response (i.e. missing digitalSignature key usage)
func createBadCertificate(privateKey, publicKey any) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certBytes)
}

func TestMakeAgentID(t *testing.T) {
	tests := []struct {
		desc         string
		template     *agentpathtemplate.Template
		sanSelectors map[string]string
		expectID     string
		expectErr    string
	}{
		{
			desc:     "default template with sha1",
			template: DefaultAgentPathTemplateCN,
			expectID: "spiffe://example.org/spire/agent/x509pop/da39a3ee5e6b4b0d3255bfef95601890afd80709",
		},
		{
			desc:     "custom template with subject identifiers",
			template: agentpathtemplate.MustParse("/foo/{{ .Subject.CommonName }}"),
			expectID: "spiffe://example.org/spire/agent/foo/test-cert",
		},
		{
			desc:         "custom template with san selectors",
			template:     agentpathtemplate.MustParse("/foo/{{ .URISanSelectors.datacenter }}/{{ .URISanSelectors.environment }}/{{ .URISanSelectors.key }}"),
			sanSelectors: map[string]string{"datacenter": "us-east-1", "environment": "production", "key": "path/to/value"},
			expectID:     "spiffe://example.org/spire/agent/foo/us-east-1/production/path/to/value",
		},
		{
			desc:      "custom template with nonexistant fields",
			template:  agentpathtemplate.MustParse("/{{ .Foo }}"),
			expectErr: `template: agent-path:1:4: executing "agent-path" at <.Foo>: can't evaluate field Foo in type x509pop.agentPathTemplateData`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			cert := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "test-cert",
				},
			}
			id, err := MakeAgentID(spiffeid.RequireTrustDomainFromString("example.org"), tt.template, cert, "", tt.sanSelectors)
			if tt.expectErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectID, id.String())
		})
	}
}
