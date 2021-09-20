package svidstore

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/x509util"
	svidstorev1 "github.com/spiffe/spire/proto/spire/plugin/agent/svidstore/v1"
)

type Secret struct {
	// The SPIFFE ID of that identify this SVID
	SpiffeID string `json:"spiffeId,omitempty"`
	// PEM encoded certificate chain. MAY invlude intermediates,
	// the leaf certificate (or SVID itself) MUST come first
	X509Svid string `json:"x509Svid,omitempty"`
	// PEM encoded PKCS#8 private key.
	X509SvidKey string `json:"x509SvidKey,omitempty"`
	// PEM encoded X.509 bundle for the trust domain
	Bundle string `json:"bundle,omitempty"`
	// CA certificate bundles belonging to foreign trust domains that the workload should trust,
	// keyed by trust domain. Bundles are in encoded in PEM format.
	FederatedBundles map[string]string `json:"federatedBundles,omitempty"`
}

func SecretFromProto(req *svidstorev1.PutX509SVIDRequest) (*Secret, error) {
	x509Svid, err := rawCertToPem(req.Svid.CertChain)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CertChain: %w", err)
	}

	x509Bundles, err := rawCertToPem(req.Svid.Bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Bundle: %w", err)
	}

	federatedBundles := make(map[string]string, len(req.FederatedBundles))
	for td, fBundle := range req.FederatedBundles {
		bundle, err := rawCertToPem([][]byte{fBundle})
		if err != nil {
			return nil, fmt.Errorf("failed to parse FederatedBundle %q: %w", td, err)
		}
		federatedBundles[td] = bundle
	}

	x509SVIDKey, err := rawKeyToPem(req.Svid.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	return &Secret{
		SpiffeID:         req.Svid.SpiffeID,
		X509Svid:         x509Svid,
		X509SvidKey:      x509SVIDKey,
		Bundle:           x509Bundles,
		FederatedBundles: federatedBundles,
	}, nil
}

// ParseMetadata parses secret data
func ParseMetadata(secretData []string) map[string]string {
	data := make(map[string]string)
	for _, s := range secretData {
		value := strings.Split(s, ":")
		data[value[0]] = value[1]
	}

	return data
}

func rawKeyToPem(rawKey []byte) (string, error) {
	key, err := x509.ParsePKCS8PrivateKey(rawKey)
	if err != nil {
		return "", err
	}

	keyPem, err := pemutil.EncodePKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}

	return string(keyPem), nil
}

func rawCertToPem(rawCerts [][]byte) (string, error) {
	certs, err := x509util.RawCertsToCertificates(rawCerts)
	if err != nil {
		return "", err
	}

	return string(pemutil.EncodeCertificates(certs)), nil
}
