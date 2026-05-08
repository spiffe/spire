package azureimds

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
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
	allowedMetadataDomains := []string{DefaultMetadataDomain}

	tests := []struct {
		name          string
		signingCert   *x509.Certificate
		expectErr     bool
		errorContains string
	}{
		{
			name: "valid signing certificate with SAN",
			signingCert: createTestCertWithIssuer(t, &x509.Certificate{
				Subject:  pkix.Name{CommonName: "metadata.azure.com"},
				DNSNames: []string{"metadata.azure.com"},
			}, "Microsoft Azure RSA TLS Issuing CA 03"),
			expectErr: false,
		},
		{
			name: "valid signing certificate with SAN but different CN",
			signingCert: createTestCertWithIssuer(t, &x509.Certificate{
				Subject:  pkix.Name{CommonName: "other.domain.com"},
				DNSNames: []string{"metadata.azure.com"},
			}, "Microsoft Azure RSA TLS Issuing CA 03"),
			expectErr: false,
		},
		{
			name: "works with any issuer name - G2 pattern",
			signingCert: createTestCertWithIssuer(t, &x509.Certificate{
				Subject:  pkix.Name{CommonName: "metadata.azure.com"},
				DNSNames: []string{"metadata.azure.com"},
			}, "Microsoft TLS G2 RSA CA OCSP 10"),
			expectErr: false,
		},
		{
			name: "works with any issuer name - old pattern",
			signingCert: createTestCertWithIssuer(t, &x509.Certificate{
				Subject:  pkix.Name{CommonName: "metadata.azure.com"},
				DNSNames: []string{"metadata.azure.com"},
			}, "Microsoft Azure RSA TLS Issuing CA 07"),
			expectErr: false,
		},
		{
			name: "missing SAN should fail",
			signingCert: createTestCertWithIssuer(t, &x509.Certificate{
				Subject:  pkix.Name{CommonName: "metadata.azure.com"},
				DNSNames: nil,
			}, "Microsoft Azure RSA TLS Issuing CA 03"),
			expectErr:     true,
			errorContains: "certificate does not have any allowed domain in SAN",
		},
		{
			name: "wrong SAN domain should fail",
			signingCert: createTestCertWithIssuer(t, &x509.Certificate{
				Subject:  pkix.Name{CommonName: "metadata.azure.com"},
				DNSNames: []string{"wrong.domain.com"},
			}, "Microsoft Azure RSA TLS Issuing CA 03"),
			expectErr:     true,
			errorContains: "certificate does not have any allowed domain in SAN",
		},
		{
			name: "multiple SANs with one matching",
			signingCert: createTestCertWithIssuer(t, &x509.Certificate{
				Subject:  pkix.Name{CommonName: "other.domain.com"},
				DNSNames: []string{"other.domain.com", "metadata.azure.com", "another.domain.com"},
			}, "Microsoft Azure RSA TLS Issuing CA 03"),
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAzureCertificates(tt.signingCert, allowedMetadataDomains)

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
			allowedMetadataDomains := []string{DefaultMetadataDomain}
			content, err := validateAttestedDocument(ctx, doc, allowedMetadataDomains)

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
