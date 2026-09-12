package client

import (
	"crypto/x509"
	"fmt"
	"os"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
)

const (
	BootstrapBundleFormatPEM    = "pem"
	BootstrapBundleFormatSPIFFE = "spiffe"
)

func loadBootstrapX509Authorities(path, format string, td spiffeid.TrustDomain) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load bootstrap bundle %q: %w", path, err)
	}

	if format == "" {
		format = BootstrapBundleFormatPEM
	}

	var certs []*x509.Certificate
	switch format {
	case BootstrapBundleFormatPEM:
		certs, err = pemutil.ParseCertificates(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bootstrap bundle %q: %w", path, err)
		}
	case BootstrapBundleFormatSPIFFE:
		bundle, err := bundleutil.Unmarshal(td, data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bootstrap bundle %q: %w", path, err)
		}
		certs = bundle.X509Authorities()
	default:
		return nil, fmt.Errorf("unknown bootstrap bundle format %q", format)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("bootstrap bundle %q contains no X.509 authorities", path)
	}
	return certs, nil
}
