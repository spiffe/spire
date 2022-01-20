package svidstore

import (
	"crypto/x509"
	"fmt"
	"strings"

	svidstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/svidstore/v1"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/x509util"
)

type Data struct {
	// SPIFFEID is the SPIFFE ID of the SVID
	SPIFFEID string `json:"spiffeID,omitempty"`
	// X509SVID is the PEM encoded certificate chain. MAY include intermediates,
	// the leaf certificate (or SVID itself) MUST come first
	X509SVID string `json:"x509SVID,omitempty"`
	// X509SVIDKey is the PEM encoded PKCS#8 private key.
	X509SVIDKey string `json:"x509SVIDKey,omitempty"`
	// Bundle is the PEM encoded X.509 bundle for the trust domain
	Bundle string `json:"bundle,omitempty"`
	// FederatedBundles is the CA certificate bundles belonging to foreign trust domains that the workload should trust,
	// keyed by trust domain. Bundles are in encoded in PEM format.
	FederatedBundles map[string]string `json:"federatedBundles,omitempty"`
}

func SecretFromProto(req *svidstorev1.PutX509SVIDRequest) (*Data, error) {
	x509SVID, err := rawCertToPem(req.Svid.CertChain)
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

	return &Data{
		SPIFFEID:         req.Svid.SpiffeID,
		X509SVID:         x509SVID,
		X509SVIDKey:      x509SVIDKey,
		Bundle:           x509Bundles,
		FederatedBundles: federatedBundles,
	}, nil
}

// ParseMetadata parses metadata from a slice of strings
// into a map that can be consumed by SVIDStore plugins
func ParseMetadata(metaData []string) (map[string]string, error) {
	data := make(map[string]string)
	for _, s := range metaData {
		value := strings.Split(s, ":")
		if len(value) < 2 {
			return nil, fmt.Errorf("metadata does not contain a colon: %q", s)
		}
		data[value[0]] = value[1]
	}

	return data, nil
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
