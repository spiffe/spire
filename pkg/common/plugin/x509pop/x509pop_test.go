package x509pop

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"text/template"

	"github.com/stretchr/testify/require"
)

const (
	testRSAKey = `-----BEGIN PRIVATE KEY-----
MIIB5QIBADANBgkqhkiG9w0BAQEFAASCAc8wggHLAgEAAmEAszTMHP/M0ETR5FjO
cUpKtxMc62olnUG2F4iSiNQ2n0YuFPRId+tDsiooNze3/WxJe5U4Ljbnw+LxYIAa
hrSbWWLbpE8ZofHmb+hNAmiXQcv40VMNtJlWHUm2O5DSsOzxAgMBAAECYCqaNpv+
Q9aPRcafRhSwsKptJMbiaSbFZGCb2xokOQgMSxA4MrIvf9xvIThfSqI4h6mNuL0g
F4+7QbSCM9oMi4lVxqtu9ThBeUmvCuuolOdvpSjDV8Y8yRrm9d9rti1g8QIxAMlz
jmSLj5kjJfSVVEMXsLZkoESvymtI44+wBwRdIbKI3Jn2cDJ2VYPNsTEVXaZLRwIx
AOO7Ob6+ya1uNLeiVtsJmaHarKn/IExvzgvr9NfNAs2PifiFKLBERSf5zh8HOocy
BwIxAMDC9/+xo0hPX6Q3t5czdf4xL0JKS5B5AHafYzeDvhjN6PjR3O4MWStziReE
cEYNRQIxAMiaajmOUpWFWMbSJ/R2tnCO8j4lUMxESJrT1TArlWaCJKVYlwj+enTG
Zj2K3pGtDQIwcHg1MNxehdkTQ7qOPHce09enVjaM0+uXPKAOfSyM7jPMBn4cm/1K
qCrBUhzFaWeg
-----END PRIVATE KEY-----`
	testECDSAKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgMmjo28H7LEOxWD2t
74mWp5XPrZwzb/VyukdPxHGOoOOhRANCAARhpK2KSCTiyeNZzrB8c2eZ4K+yZGrp
4MpWREMXQMIwbP/QWGYXQ8GWhp16J6IYXkywB/SJnKPY+iV6Mnbxp31K
-----END PRIVATE KEY-----`
)

func TestChallengeResponse(t *testing.T) {
	require := require.New(t)

	// load up RSA key and create a self-signed certificate over the public key
	pemBlock, _ := pem.Decode([]byte(testRSAKey))
	require.NotNil(pemBlock)
	privateKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	require.NoError(err)
	rsaPrivateKey := privateKey.(*rsa.PrivateKey)
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
	pemBlock, _ = pem.Decode([]byte(testECDSAKey))
	require.NotNil(pemBlock)
	privateKey, err = x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	require.NoError(err)
	ecdsaPrivateKey := privateKey.(*ecdsa.PrivateKey)
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

func createCertificate(privateKey, publicKey interface{}) (*x509.Certificate, error) {
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
func createBadCertificate(privateKey, publicKey interface{}) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certBytes)
}

func TestMakeSPIFFEID(t *testing.T) {
	tests := []struct {
		desc         string
		template     *template.Template
		expectSPIFFE string
		expectErr    string
	}{
		{
			desc:         "default template with sha1",
			template:     DefaultAgentPathTemplate,
			expectSPIFFE: "spiffe://example.org/spire/agent/x509pop/da39a3ee5e6b4b0d3255bfef95601890afd80709",
		},
		{
			desc:         "custom template with subject identifiers",
			template:     template.Must(template.New("test").Parse("foo/{{ .Subject.CommonName }}")),
			expectSPIFFE: "spiffe://example.org/spire/agent/foo/test-cert",
		},
		{
			desc:      "custom template with nonexistant fields",
			template:  template.Must(template.New("test").Parse("{{ .Foo }}")),
			expectErr: `template: test:1:3: executing "test" at <.Foo>: can't evaluate field Foo in type x509pop.agentPathTemplateData`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			cert := &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "test-cert",
				},
			}
			spiffeid, err := MakeSpiffeID("example.org", tt.template, cert)
			if tt.expectErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectSPIFFE, spiffeid)
		})
	}
}
