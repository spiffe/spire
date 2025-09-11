package azureimds

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/smallstep/pkcs7"
	"github.com/spiffe/spire/pkg/common/plugin/azure"
)

// ValidateAttestedDocument validates the Azure IMDS attested document signature
func validateAttestedDocument(ctx context.Context, doc *azure.AttestedDocument) (*azure.AttestedDocumentContent, error) {
	if doc.Signature == "" {
		return nil, fmt.Errorf("missing signature in attested document")
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
		return nil, fmt.Errorf("no certificates found in PKCS7 signature")
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
	if err := validateAzureCertificates(signingCert, intermediateCert); err != nil {
		return nil, fmt.Errorf("Azure certificate validation failed: %w", err)
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
	var caIssuersURL string
	for _, url := range signingCert.IssuingCertificateURL {
		if url != "" {
			caIssuersURL = url
			break
		}
	}

	if caIssuersURL == "" {
		return nil, fmt.Errorf("no CA Issuers URL found in signing certificate")
	}

	// Fetch the intermediate certificate
	req, err := http.NewRequestWithContext(ctx, "GET", caIssuersURL, nil)
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
		// Try parsing as PEM
		block, _ := pem.Decode(certData)
		if block == nil {
			return nil, fmt.Errorf("failed to decode intermediate certificate as PEM")
		}
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse intermediate certificate: %w", err)
		}
	}

	return cert, nil
}

// Azure-specific certificate validation constants
const (
	// Expected subject patterns for Azure certificates
	AzureMetadataSubject = "metadata.azure.com"

	// Expected issuer patterns
	MicrosoftAzureRSATLSIssuer = "Microsoft Azure RSA TLS Issuing CA"
	DigiCertGlobalRootCA       = "DigiCert Global Root G2"
)

// validateAzureCertificates performs Azure-specific certificate validation
func validateAzureCertificates(signingCert, intermediateCert *x509.Certificate) error {
	// Validate signing certificate subject
	if err := validateCertificateSubject(signingCert, AzureMetadataSubject); err != nil {
		return fmt.Errorf("signing certificate subject validation failed: %w", err)
	}

	// Validate signing certificate issuer
	if err := validateCertificateIssuer(signingCert, MicrosoftAzureRSATLSIssuer); err != nil {
		return fmt.Errorf("signing certificate issuer validation failed: %w", err)
	}

	if intermediateCert != nil {
		// Validate intermediate certificate subject
		if err := validateCertificateIssuer(intermediateCert, DigiCertGlobalRootCA); err != nil {
			return fmt.Errorf("intermediate certificate issuer validation failed: %w", err)
		}

		// Validate intermediate certificate issuer
		if err := validateCertificateSubject(intermediateCert, MicrosoftAzureRSATLSIssuer); err != nil {
			return fmt.Errorf("intermediate certificate subject validation failed: %w", err)
		}
	}

	return nil
}

// validateCertificateSubject validates that the certificate subject contains the expected value
func validateCertificateSubject(cert *x509.Certificate, expectedSubject string) error {
	subject := cert.Subject.CommonName
	if subject == "" {
		return fmt.Errorf("certificate has no common name in subject")
	}

	if !strings.Contains(subject, expectedSubject) {
		return fmt.Errorf("certificate subject '%s' does not contain expected value '%s'", subject, expectedSubject)
	}

	return nil
}

// validateCertificateIssuer validates that the certificate issuer contains the expected value
func validateCertificateIssuer(cert *x509.Certificate, expectedIssuer string) error {
	issuer := cert.Issuer.CommonName
	if issuer == "" {
		return fmt.Errorf("certificate has no common name in issuer")
	}

	if !strings.Contains(issuer, expectedIssuer) {
		return fmt.Errorf("certificate issuer '%s' does not contain expected value '%s'", issuer, expectedIssuer)
	}

	return nil
}

// validateCertificateChain validates the certificate chain against the DigiCert Global Root CA
func validateCertificateChain(signingCert, intermediateCert *x509.Certificate) error {
	// Create certificate pool with intermediate certificate
	intermediates := x509.NewCertPool()
	if intermediateCert != nil {
		intermediates.AddCert(intermediateCert)
	}

	// For Azure operated by 21Vianet, we would need the DigiCert Global Root CA
	// For now, we'll validate the chain structure without the root CA
	// In production, you would load the DigiCert Global Root CA certificate

	// Verify the signing certificate against the intermediate
	if intermediateCert != nil {
		// Check that the signing certificate was issued by the intermediate
		if err := signingCert.CheckSignatureFrom(intermediateCert); err != nil {
			return fmt.Errorf("signing certificate was not issued by intermediate certificate: %w", err)
		}
		fmt.Println("✅ Signing certificate chain validation passed")
	}

	opts := x509.VerifyOptions{
		Intermediates: intermediates,
	}
	_, err := signingCert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}

	return nil
}
