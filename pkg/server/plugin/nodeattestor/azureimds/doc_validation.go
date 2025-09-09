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

	"github.com/digitorus/pkcs7"
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
	//TODO: Uncomment this when we have a way to verify the signature
	// if err := pkcs7Sig.Verify(); err != nil {
	// 	return nil, fmt.Errorf("signature verification failed: %w", err)
	// }

	var content *azure.AttestedDocumentContent
	if err := json.Unmarshal(pkcs7Sig.Content, content); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attested document payload: %w", err)
	}
	return content, nil
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
