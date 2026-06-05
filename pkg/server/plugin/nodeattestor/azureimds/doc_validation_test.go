package azureimds

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
	"github.com/spiffe/spire/pkg/common/plugin/azure"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
)

func TestExtractIssuerURL(t *testing.T) {
	tests := []struct {
		name          string
		cert          *x509.Certificate
		expectErr     bool
		expectedURL   string
		errorContains string
	}{
		{
			name: "valid certificate with CA Issuers URL",
			cert: createTestCert(t, &x509.Certificate{
				IssuingCertificateURL: []string{"https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2001.crt"},
			}),
			expectErr:   false,
			expectedURL: "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2001.crt",
		},
		{
			name: "certificate with multiple URLs - uses first non-empty",
			cert: createTestCert(t, &x509.Certificate{
				IssuingCertificateURL: []string{"", "https://www.microsoft.com/pkiops/certs/cert.crt", "https://example.com/cert.crt"},
			}),
			expectErr:   false,
			expectedURL: "https://www.microsoft.com/pkiops/certs/cert.crt",
		},
		{
			name: "certificate with empty CA Issuers URLs",
			cert: createTestCert(t, &x509.Certificate{
				IssuingCertificateURL: []string{},
			}),
			expectErr:     true,
			errorContains: "no CA Issuers URL found",
		},
		{
			name: "certificate with only empty URLs",
			cert: createTestCert(t, &x509.Certificate{
				IssuingCertificateURL: []string{"", ""},
			}),
			expectErr:     true,
			errorContains: "no CA Issuers URL found",
		},
		{
			name: "certificate with invalid URL format",
			cert: createTestCert(t, &x509.Certificate{
				IssuingCertificateURL: []string{":://invalid-url"},
			}),
			expectErr:     true,
			errorContains: "failed to parse CA Issuers URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := extractIssuerURL(tt.cert)

			if tt.expectErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorContains)
				require.Nil(t, u)
			} else {
				require.NoError(t, err)
				require.NotNil(t, u)
				require.Equal(t, tt.expectedURL, u.String())
			}
		})
	}
}

func TestValidateCertificateSubject(t *testing.T) {
	tests := []struct {
		name          string
		cert          *x509.Certificate
		expected      *regexp.Regexp
		expectErr     bool
		errorContains string
	}{
		{
			name: "valid subject matching expected value",
			cert: createTestCert(t, &x509.Certificate{
				Subject: pkix.Name{CommonName: "metadata.azure.com"},
			}),
			expected:  AzureMetadataSubject,
			expectErr: false,
		},
		{
			name: "empty CommonName in subject",
			cert: createTestCert(t, &x509.Certificate{
				Subject: pkix.Name{CommonName: ""},
			}),
			expected:      AzureMetadataSubject,
			expectErr:     true,
			errorContains: "certificate has no common name in subject",
		},
		{
			name: "subject mismatch",
			cert: createTestCert(t, &x509.Certificate{
				Subject: pkix.Name{CommonName: "wrong.subject.com"},
			}),
			expected:      AzureMetadataSubject,
			expectErr:     true,
			errorContains: "certificate subject",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCertificateSubject(tt.cert, tt.expected)

			if tt.expectErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateCertificateIssuer(t *testing.T) {
	tests := []struct {
		name          string
		cert          *x509.Certificate
		expected      *regexp.Regexp
		expectErr     bool
		errorContains string
	}{
		{
			name:      "valid issuer with numbered CA 03",
			cert:      createTestCertWithIssuer(t, &x509.Certificate{}, "Microsoft Azure RSA TLS Issuing CA 03"),
			expected:  MicrosoftAzureRSATLSIssuer,
			expectErr: false,
		},
		{
			name:      "valid issuer with numbered CA 07",
			cert:      createTestCertWithIssuer(t, &x509.Certificate{}, "Microsoft Azure RSA TLS Issuing CA 07"),
			expected:  MicrosoftAzureRSATLSIssuer,
			expectErr: false,
		},
		{
			name:      "valid issuer with numbered CA 08",
			cert:      createTestCertWithIssuer(t, &x509.Certificate{}, "Microsoft Azure RSA TLS Issuing CA 08"),
			expected:  MicrosoftAzureRSATLSIssuer,
			expectErr: false,
		},
		{
			name:      "valid issuer with numbered CA 04",
			cert:      createTestCertWithIssuer(t, &x509.Certificate{}, "Microsoft Azure RSA TLS Issuing CA 04"),
			expected:  MicrosoftAzureRSATLSIssuer,
			expectErr: false,
		},
		{
			name: "empty CommonName in issuer",
			cert: createTestCert(t, &x509.Certificate{
				Issuer: pkix.Name{CommonName: ""},
			}),
			expected:      MicrosoftAzureRSATLSIssuer,
			expectErr:     true,
			errorContains: "certificate has no common name in issuer",
		},
		{
			name:          "issuer mismatch",
			cert:          createTestCertWithIssuer(t, &x509.Certificate{}, "Wrong Issuer"),
			expected:      MicrosoftAzureRSATLSIssuer,
			expectErr:     true,
			errorContains: "certificate issuer",
		},
		{
			name:          "base string without number should fail",
			cert:          createTestCertWithIssuer(t, &x509.Certificate{}, "Microsoft Azure RSA TLS Issuing CA"),
			expected:      MicrosoftAzureRSATLSIssuer,
			expectErr:     true,
			errorContains: "certificate issuer",
		},
		{
			name:          "invalid numbered format - single digit",
			cert:          createTestCertWithIssuer(t, &x509.Certificate{}, "Microsoft Azure RSA TLS Issuing CA 1"),
			expected:      MicrosoftAzureRSATLSIssuer,
			expectErr:     true,
			errorContains: "certificate issuer",
		},
		{
			name:          "invalid numbered format - three digits",
			cert:          createTestCertWithIssuer(t, &x509.Certificate{}, "Microsoft Azure RSA TLS Issuing CA 123"),
			expected:      MicrosoftAzureRSATLSIssuer,
			expectErr:     true,
			errorContains: "certificate issuer",
		},
		{
			name:          "invalid numbered format - non-numeric suffix",
			cert:          createTestCertWithIssuer(t, &x509.Certificate{}, "Microsoft Azure RSA TLS Issuing CA abc"),
			expected:      MicrosoftAzureRSATLSIssuer,
			expectErr:     true,
			errorContains: "certificate issuer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCertificateIssuer(tt.cert, tt.expected)

			if tt.expectErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGetIntermediateCertificate(t *testing.T) {
	tests := []struct {
		name          string
		cert          *x509.Certificate
		expectErr     bool
		errorContains string
	}{
		{
			name: "wrong host in CA Issuers URL",
			cert: createTestCert(t, &x509.Certificate{
				IssuingCertificateURL: []string{"https://example.com/cert.crt"},
			}),
			expectErr:     true,
			errorContains: "CA Issuers URL host",
		},
		{
			name: "no CA Issuers URL",
			cert: createTestCert(t, &x509.Certificate{
				IssuingCertificateURL: []string{},
			}),
			expectErr:     true,
			errorContains: "failed to extract CA Issuers URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			cert, err := getIntermediateCertificate(ctx, tt.cert)

			if tt.expectErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorContains)
				require.Nil(t, cert)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cert)
			}
		})
	}
}

func TestValidateAzureCertificates(t *testing.T) {
	tests := []struct {
		name             string
		signingCert      *x509.Certificate
		intermediateCert *x509.Certificate
		expectErr        bool
		errorContains    string
	}{
		{
			name: "valid signing and intermediate certificates",
			signingCert: createTestCertWithIssuer(t, &x509.Certificate{
				Subject: pkix.Name{CommonName: "metadata.azure.com"},
			}, "Microsoft Azure RSA TLS Issuing CA 03"),
			intermediateCert: createTestCertWithIssuer(t, &x509.Certificate{
				Subject: pkix.Name{CommonName: "Microsoft Azure RSA TLS Issuing CA 03"},
			}, "DigiCert Global Root G2"),
			expectErr: false,
		},
		{
			name: "nil intermediate certificate - should still validate signing cert",
			signingCert: createTestCertWithIssuer(t, &x509.Certificate{
				Subject: pkix.Name{CommonName: "metadata.azure.com"},
			}, "Microsoft Azure RSA TLS Issuing CA 03"),
			intermediateCert: nil,
			expectErr:        false,
		},
		{
			name: "valid signing certificate with numbered CA 03",
			signingCert: createTestCertWithIssuer(t, &x509.Certificate{
				Subject: pkix.Name{CommonName: "metadata.azure.com"},
			}, "Microsoft Azure RSA TLS Issuing CA 03"),
			intermediateCert: nil,
			expectErr:        false,
		},
		{
			name: "valid intermediate certificate with numbered CA 07",
			signingCert: createTestCertWithIssuer(t, &x509.Certificate{
				Subject: pkix.Name{CommonName: "metadata.azure.com"},
			}, "Microsoft Azure RSA TLS Issuing CA 07"),
			intermediateCert: createTestCertWithIssuer(t, &x509.Certificate{
				Subject: pkix.Name{CommonName: "Microsoft Azure RSA TLS Issuing CA 07"},
			}, "DigiCert Global Root G2"),
			expectErr: false,
		},
		{
			name: "invalid signing certificate subject",
			signingCert: createTestCertWithIssuer(t, &x509.Certificate{
				Subject: pkix.Name{CommonName: "wrong.subject.com"},
			}, "Microsoft Azure RSA TLS Issuing CA 03"),
			intermediateCert: nil,
			expectErr:        true,
			errorContains:    "signing certificate subject validation failed",
		},
		{
			name: "invalid signing certificate issuer",
			signingCert: createTestCertWithIssuer(t, &x509.Certificate{
				Subject: pkix.Name{CommonName: "metadata.azure.com"},
			}, "Wrong Issuer"),
			intermediateCert: nil,
			expectErr:        true,
			errorContains:    "signing certificate issuer validation failed",
		},
		{
			name: "invalid intermediate certificate issuer",
			signingCert: createTestCertWithIssuer(t, &x509.Certificate{
				Subject: pkix.Name{CommonName: "metadata.azure.com"},
			}, "Microsoft Azure RSA TLS Issuing CA 03"),
			intermediateCert: createTestCertWithIssuer(t, &x509.Certificate{
				Subject: pkix.Name{CommonName: "Microsoft Azure RSA TLS Issuing CA 03"},
			}, "Wrong Root CA"),
			expectErr:     true,
			errorContains: "intermediate certificate issuer validation failed",
		},
		{
			name: "invalid intermediate certificate subject",
			signingCert: createTestCertWithIssuer(t, &x509.Certificate{
				Subject: pkix.Name{CommonName: "metadata.azure.com"},
			}, "Microsoft Azure RSA TLS Issuing CA 03"),
			intermediateCert: createTestCertWithIssuer(t, &x509.Certificate{
				Subject: pkix.Name{CommonName: "Wrong Intermediate"},
			}, "DigiCert Global Root G2"),
			expectErr:     true,
			errorContains: "intermediate certificate subject validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAzureCertificates(tt.signingCert, tt.intermediateCert)

			if tt.expectErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateCertificateChain(t *testing.T) {
	tests := []struct {
		name          string
		setupCerts    func() (*x509.Certificate, *x509.Certificate)
		expectErr     bool
		errorContains string
	}{
		{
			name: "signing cert not issued by intermediate",
			setupCerts: func() (*x509.Certificate, *x509.Certificate) {
				// Create two unrelated certificates
				signingCert := createTestCert(t, &x509.Certificate{
					Subject: pkix.Name{CommonName: "metadata.azure.com"},
				})
				intermediateCert := createTestCert(t, &x509.Certificate{
					Subject: pkix.Name{CommonName: "Microsoft Azure RSA TLS Issuing CA"},
				})
				return signingCert, intermediateCert
			},
			expectErr:     true,
			errorContains: "signing certificate was not issued by intermediate certificate",
		},
		{
			name: "nil intermediate certificate",
			setupCerts: func() (*x509.Certificate, *x509.Certificate) {
				// Create a signing cert that can't verify against roots
				signingCert := createTestCert(t, &x509.Certificate{
					Subject: pkix.Name{CommonName: "metadata.azure.com"},
				})
				return signingCert, nil
			},
			expectErr:     true,
			errorContains: "certificate chain validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signingCert, intermediateCert := tt.setupCerts()
			err := validateCertificateChain(signingCert, intermediateCert)

			if tt.expectErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateAttestedDocument(t *testing.T) {
	// Create a valid PKCS7 signature for testing
	createValidPKCS7 := func(t *testing.T, content []byte, serverURL string) string {
		rootKey := testkey.NewEC256(t)
		rootCert := spiretest.SelfSignCertificateWithKey(t, &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "DigiCert Global Root G2"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour * 24 * 365),
			IsCA:         true,
		}, rootKey)

		intermediateKey := testkey.NewEC256(t)
		intermediateCert := spiretest.CreateCertificate(t, &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "Microsoft Azure RSA TLS Issuing CA 03"},
			Issuer:       pkix.Name{CommonName: "DigiCert Global Root G2"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour * 24 * 365),
			IsCA:         true,
		}, rootCert, intermediateKey.Public(), rootKey)

		issuerURL := "https://www.microsoft.com/pkiops/certs/cert.crt"
		if serverURL != "" {
			issuerURL = serverURL + "/cert.crt"
		}

		signingKey := testkey.NewEC256(t)
		signingCert := spiretest.CreateCertificate(t, &x509.Certificate{
			SerialNumber:          big.NewInt(3),
			Subject:               pkix.Name{CommonName: "metadata.azure.com"},
			Issuer:                pkix.Name{CommonName: "Microsoft Azure RSA TLS Issuing CA 03"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour * 24 * 365),
			IssuingCertificateURL: []string{issuerURL},
		}, intermediateCert, signingKey.Public(), intermediateKey)

		// Create PKCS7 signature
		signedData, err := pkcs7.NewSignedData(content)
		require.NoError(t, err)
		err = signedData.AddSigner(signingCert, signingKey, pkcs7.SignerInfoConfig{})
		require.NoError(t, err)
		signedData.Detach()
		signature, err := signedData.Finish()
		require.NoError(t, err)

		return base64.StdEncoding.EncodeToString(signature)
	}

	tests := []struct {
		name          string
		setupDoc      func() *azure.AttestedDocument
		expectErr     bool
		errorContains string
	}{
		{
			name: "missing signature",
			setupDoc: func() *azure.AttestedDocument {
				return &azure.AttestedDocument{
					Encoding:  "pkcs7-signature",
					Signature: "",
				}
			},
			expectErr:     true,
			errorContains: "missing signature",
		},
		{
			name: "invalid base64 signature",
			setupDoc: func() *azure.AttestedDocument {
				return &azure.AttestedDocument{
					Encoding:  "pkcs7-signature",
					Signature: "not-valid-base64!!!",
				}
			},
			expectErr:     true,
			errorContains: "failed to decode signature",
		},
		{
			name: "invalid PKCS7 signature format",
			setupDoc: func() *azure.AttestedDocument {
				invalidSig := base64.StdEncoding.EncodeToString([]byte("not a valid pkcs7 signature"))
				return &azure.AttestedDocument{
					Encoding:  "pkcs7-signature",
					Signature: invalidSig,
				}
			},
			expectErr:     true,
			errorContains: "failed to parse PKCS7 signature",
		},
		{
			name: "no certificates in PKCS7 signature",
			setupDoc: func() *azure.AttestedDocument {
				// Create a PKCS7 signature without certificates by creating signed data
				// but not adding any signers (which would add certificates)
				content := []byte(`{"subscriptionId":"sub-123","vmId":"vm-123","nonce":"nonce-123"}`)
				signedData, err := pkcs7.NewSignedData(content)
				require.NoError(t, err)
				signedData.Detach()
				// Finish without adding a signer - this creates a signature with no certificates
				signature, err := signedData.Finish()
				require.NoError(t, err)
				return &azure.AttestedDocument{
					Encoding:  "pkcs7-signature",
					Signature: base64.StdEncoding.EncodeToString(signature),
				}
			},
			expectErr:     true,
			errorContains: "no certificates found in PKCS7 signature",
		},
		{
			name: "failed intermediate certificate fetch",
			setupDoc: func() *azure.AttestedDocument {
				content := []byte(`{"subscriptionId":"sub-123","vmId":"vm-123","nonce":"nonce-123"}`)
				// Use an invalid URL that will fail
				sig := createValidPKCS7(t, content, "https://invalid-host-that-does-not-exist-12345.local")
				return &azure.AttestedDocument{
					Encoding:  "pkcs7-signature",
					Signature: sig,
				}
			},
			expectErr:     true,
			errorContains: "failed to get intermediate certificate",
		},
		{
			name: "invalid JSON payload",
			setupDoc: func() *azure.AttestedDocument {
				// Create PKCS7 with invalid JSON content
				invalidContent := []byte("not valid json")
				// Use an invalid URL since we can't test the full flow with host validation
				sig := createValidPKCS7(t, invalidContent, "https://invalid-host-that-does-not-exist-12345.local")
				return &azure.AttestedDocument{
					Encoding:  "pkcs7-signature",
					Signature: sig,
				}
			},
			expectErr:     true,
			errorContains: "failed to get intermediate certificate", // Will fail before JSON parsing due to host validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := tt.setupDoc()

			ctx := context.Background()
			content, err := validateAttestedDocument(ctx, doc)

			if tt.expectErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorContains)
				require.Nil(t, content)
			} else {
				require.NoError(t, err)
				require.NotNil(t, content)
			}
		})
	}
}

// Helper function to create a test certificate
func createTestCert(t *testing.T, template *x509.Certificate) *x509.Certificate {
	// Set defaults if not provided
	if template.SerialNumber == nil {
		template.SerialNumber = big.NewInt(1)
	}
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now().Add(-time.Hour)
	}
	if template.NotAfter.IsZero() {
		template.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	}

	// Use spiretest helper to create certificate
	cert, _ := spiretest.SelfSignCertificate(t, template)
	return cert
}

// Helper function to create a test certificate with a specific issuer name
func createTestCertWithIssuer(t *testing.T, template *x509.Certificate, issuerCN string) *x509.Certificate {
	// Set defaults if not provided
	if template.SerialNumber == nil {
		template.SerialNumber = big.NewInt(1)
	}
	if template.NotBefore.IsZero() {
		template.NotBefore = time.Now().Add(-time.Hour)
	}
	if template.NotAfter.IsZero() {
		template.NotAfter = time.Now().Add(time.Hour * 24 * 365)
	}

	// Create a parent certificate with the desired issuer name
	parentKey := testkey.NewEC256(t)
	parentTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject:      pkix.Name{CommonName: issuerCN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
		IsCA:         true,
	}
	parentCert := spiretest.SelfSignCertificateWithKey(t, parentTemplate, parentKey)

	// Create the certificate signed by the parent
	certKey := testkey.NewEC256(t)
	cert := spiretest.CreateCertificate(t, template, parentCert, certKey.Public(), parentKey)
	return cert
}

// TestValidateAttestedDocumentRejectsContentSignedByNonAzureCertificate ensures
// that a document whose content is signed by a non-Azure certificate is
// rejected even when a genuine Azure metadata certificate is placed first in
// the PKCS#7 certificate bag. The bag is attacker controlled and unordered, so
// the certificate that signed the content (resolved from SignerInfo) must be
// the same one that Azure and chain validation run against. Validating the
// first certificate in the bag instead allowed attacker-signed content to be
// accepted.
func TestValidateAttestedDocumentRejectsContentSignedByNonAzureCertificate(t *testing.T) {
	originalRoots := roots
	originalTransport := http.DefaultClient.Transport
	t.Cleanup(func() {
		roots = originalRoots
		http.DefaultClient.Transport = originalTransport
	})

	// Trust a test root so the genuine Azure chain validates.
	rootKey := testkey.NewEC256(t)
	rootCert := spiretest.SelfSignCertificateWithKey(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "DigiCert Global Root G2"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, rootKey)
	roots = []string{string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootCert.Raw,
	}))}

	intermediateKey := testkey.NewEC256(t)
	intermediateCert := spiretest.CreateCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Microsoft Azure RSA TLS Issuing CA 03"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, rootCert, intermediateKey.Public(), rootKey)

	// Serve the intermediate certificate for the CA Issuers lookup.
	http.DefaultClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		require.Equal(t, "https", req.URL.Scheme)
		require.Equal(t, MicrosoftIntermediateIssuerHost, req.URL.Host)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(intermediateCert.Raw)),
			Header:     make(http.Header),
		}, nil
	})

	// A genuine Azure metadata certificate that chains to the trusted root. It
	// is placed in the bag but does not sign the content.
	azureMetadataKey := testkey.NewEC256(t)
	azureMetadataCert := spiretest.CreateCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "metadata.azure.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IssuingCertificateURL: []string{"https://www.microsoft.com/pkiops/certs/test-azure-intermediate.crt"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, intermediateCert, azureMetadataKey.Public(), intermediateKey)

	// The attacker-controlled certificate that actually signs the content. It
	// advertises the same Microsoft CA Issuers host so validation proceeds to
	// Azure certificate validation, which rejects the non-Azure subject.
	attackerKey := testkey.NewEC256(t)
	attackerCert := spiretest.SelfSignCertificateWithKey(t, &x509.Certificate{
		SerialNumber:          big.NewInt(4),
		Subject:               pkix.Name{CommonName: "attacker.example.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IssuingCertificateURL: []string{"https://www.microsoft.com/pkiops/certs/test-azure-intermediate.crt"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}, attackerKey)

	signedData, err := pkcs7.NewSignedData([]byte(`{"subscriptionId":"attacker-subscription","vmId":"550e8400-e29b-41d4-a716-446655440000","nonce":"server-nonce"}`))
	require.NoError(t, err)

	// Place the Azure certificate first in the bag, then sign with the attacker
	// certificate so SignerInfo points at the non-Azure signer.
	signedData.AddCertificate(azureMetadataCert)
	require.NoError(t, signedData.AddSigner(attackerCert, attackerKey, pkcs7.SignerInfoConfig{}))

	signature, err := signedData.Finish()
	require.NoError(t, err)

	content, err := validateAttestedDocument(context.Background(), &azure.AttestedDocument{
		Encoding:  "pkcs7-signature",
		Signature: base64.StdEncoding.EncodeToString(signature),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "azure certificate validation failed")
	require.Nil(t, content)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
