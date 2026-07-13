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
	"strings"
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
func validateAttestedDocument(ctx context.Context, doc *azure.AttestedDocument, allowedMetadataDomains []string, additionalRoots []*x509.Certificate) (*azure.AttestedDocumentContent, error) {
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

	// Step 3: Extract the signing certificate. The PKCS#7 certificate bag is
	// unordered and may carry certificates that did not sign the content, so we
	// resolve the actual signer instead of assuming it is the first entry. This
	// keeps the certificate that Azure and chain validation run against in sync
	// with the certificate that Verify uses to check the signature.
	if len(pkcs7Sig.Certificates) == 0 {
		return nil, errors.New("no certificates found in PKCS7 signature")
	}

	signingCert := pkcs7Sig.GetOnlySigner()
	if signingCert == nil {
		return nil, errors.New("expected exactly one signer certificate in PKCS7 signature")
	}

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
	if err := validateAzureCertificate(signingCert, allowedMetadataDomains); err != nil {
		return nil, fmt.Errorf("signing certificate validation failed: %w", err)
	}

	// Step 8: Validate certificate chain
	if err := validateCertificateChain(signingCert, intermediateCert, additionalRoots); err != nil {
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

// validateAzureCertificate performs Azure-specific certificate validation.
// Following Azure's recommendation to validate the certificate Subject Alternative Name (SAN)
// See: https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service?tabs=linux#signature-validation-guidance
func validateAzureCertificate(cert *x509.Certificate, baseDomains []string) error {
	// Check SAN DNS names against each allowed base domain
	for _, dnsName := range cert.DNSNames {
		for _, baseDomain := range baseDomains {
			// Accept exact match with base domain
			if dnsName == baseDomain {
				return nil
			}

			// Accept any subdomain under the base domain (e.g., eastus.metadata.azure.com, sub.eastus.metadata.azure.com)
			suffix := "." + baseDomain
			if strings.HasSuffix(dnsName, suffix) {
				return nil
			}
		}
	}

	return fmt.Errorf("certificate does not have any valid domain in SAN (found SANs=%v, allowed domains=%v)",
		cert.DNSNames, baseDomains)
}

// validateCertificateChain validates the certificate chain against the embedded
// roots plus any operator-configured additional roots.
func validateCertificateChain(signingCert, intermediateCert *x509.Certificate, additionalRoots []*x509.Certificate) error {
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
	for i, c := range roots {
		if !rootCerts.AppendCertsFromPEM([]byte(c)) {
			return fmt.Errorf("failed to parse root certificate at index %d", i)
		}
	}
	for _, c := range additionalRoots {
		rootCerts.AddCert(c)
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
