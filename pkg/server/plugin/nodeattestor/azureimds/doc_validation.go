package azureimds

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/smallstep/pkcs7"
	"github.com/spiffe/spire/pkg/common/plugin/azure"
)

const (
	// Default metadata domain for commercial Azure
	DefaultMetadataDomain = "metadata.azure.com"

	// Expected microsoft issuer host for intermediate certificate fetching
	MicrosoftIntermediateIssuerHost = "www.microsoft.com"
)

// ValidateAttestedDocument validates the Azure IMDS attested document signature
func validateAttestedDocument(ctx context.Context, doc *azure.AttestedDocument, allowedMetadataDomains []string) (*azure.AttestedDocumentContent, error) {
	if doc.Signature == "" {
		return nil, errors.New("missing signature in attested document")
	}

	// Step 1: Base64 decode the signature
	decodedSignature, err := base64.StdEncoding.DecodeString(doc.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	// Step 2: Parse the PKCS7 signature
	pkcs7Sig, err := pkcs7.Parse(decodedSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS7 signature: %w", err)
	}

	// Step 3: Extract the signing certificate
	if len(pkcs7Sig.Certificates) == 0 {
		return nil, errors.New("no certificates found in PKCS7 signature")
	}

	signingCert := pkcs7Sig.Certificates[0]

	// Step 4: Get the intermediate certificate from CA Issuers extension
	intermediateCert, err := getIntermediateCertificate(ctx, signingCert)
	if err != nil {
		return nil, fmt.Errorf("failed to get intermediate certificate: %w", err)
	}

	// Step 5: Add certificates to PKCS7 for verification
	if intermediateCert != nil {
		pkcs7Sig.Certificates = append(pkcs7Sig.Certificates, intermediateCert)
	}

	// Step 6: Verify the signature
	if err := pkcs7Sig.Verify(); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Step 7: Perform Azure-specific certificate validation
	if err := validateAzureCertificates(signingCert, allowedMetadataDomains); err != nil {
		return nil, fmt.Errorf("azure certificate validation failed: %w", err)
	}

	// Step 8: Validate certificate chain
	if err := validateCertificateChain(signingCert, intermediateCert); err != nil {
		return nil, fmt.Errorf("certificate chain validation failed: %w", err)
	}

	// Final step: Unmarshal the attested document payload
	var content azure.AttestedDocumentContent
	if err := json.Unmarshal(pkcs7Sig.Content, &content); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attested document payload: %w", err)
	}
	return &content, nil
}

// getIntermediateCertificate fetches the intermediate certificate from the CA Issuers URL
func getIntermediateCertificate(ctx context.Context, signingCert *x509.Certificate) (*x509.Certificate, error) {
	// Extract CA Issuers URL from the signing certificate
	caIssuersURL, err := extractIssuerURL(signingCert)
	if err != nil {
		return nil, fmt.Errorf("failed to extract CA Issuers URL: %w", err)
	}

	if caIssuersURL.Host != MicrosoftIntermediateIssuerHost {
		return nil, fmt.Errorf("CA Issuers URL host %q does not match expected value %q", caIssuersURL.Host, MicrosoftIntermediateIssuerHost)
	}

	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	// Fetch the intermediate certificate
	req, err := http.NewRequestWithContext(ctx, "GET", caIssuersURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for intermediate certificate: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch intermediate certificate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch intermediate certificate, status: %d", resp.StatusCode)
	}

	certData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read intermediate certificate: %w", err)
	}

	// Try parsing as DER first, then PEM
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		block, _ := pem.Decode(certData)
		if block == nil {
			return nil, errors.New("failed to decode intermediate certificate as PEM")
		}
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse intermediate certificate: %w", err)
		}
	}

	return cert, nil
}

// validateAzureCertificates performs Azure-specific certificate validation
// Following Azure's recommendation to validate the certificate Subject Alternative Name (SAN)
// to confirm it's from Azure, rather than pinning specific intermediate CA names.
// See: https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service?tabs=linux#signature-validation-guidance
func validateAzureCertificates(signingCert *x509.Certificate, allowedMetadataDomains []string) error {
	if err := validateAzureCertificate(signingCert, allowedMetadataDomains); err != nil {
		return fmt.Errorf("signing certificate validation failed: %w", err)
	}
	return nil
}

// validateAzureCertificate validates that the certificate is for an allowed Azure metadata domain
// by checking the Subject Alternative Name (SAN) extension. Per RFC 6125 and modern PKI standards,
// SAN is the authoritative source for certificate identity validation (Subject CN is deprecated).
func validateAzureCertificate(cert *x509.Certificate, allowedDomains []string) error {
	// Check SAN DNS names
	for _, dnsName := range cert.DNSNames {
		for _, allowedDomain := range allowedDomains {
			if dnsName == allowedDomain {
				return nil
			}
		}
	}

	return fmt.Errorf("certificate does not have any allowed domain in SAN (found SANs=%v, allowed=%v)",
		cert.DNSNames, allowedDomains)
}

// validateCertificateChain validates the certificate chain against the DigiCert Global Root CA
func validateCertificateChain(signingCert, intermediateCert *x509.Certificate) error {
	intermediates := x509.NewCertPool()
	if intermediateCert != nil {
		intermediates.AddCert(intermediateCert)
	}

	if intermediateCert != nil {
		// Check that the signing certificate was issued by the intermediate
		if err := signingCert.CheckSignatureFrom(intermediateCert); err != nil {
			return fmt.Errorf("signing certificate was not issued by intermediate certificate: %w", err)
		}
	}
	rootCerts := x509.NewCertPool()
	for _, c := range roots {
		rootCerts.AppendCertsFromPEM([]byte(c))
	}
	opts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         rootCerts,
	}
	_, err := signingCert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}

	return nil
}

func extractIssuerURL(cert *x509.Certificate) (*url.URL, error) {
	for _, issuerUrl := range cert.IssuingCertificateURL {
		if issuerUrl != "" {
			u, err := url.Parse(issuerUrl)
			if err != nil {
				return nil, fmt.Errorf("failed to parse CA Issuers URL: %w", err)
			}

			return u, nil
		}
	}

	return nil, errors.New("no CA Issuers URL found in certificate")
}
