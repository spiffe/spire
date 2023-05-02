package awsiid

import (
	"crypto/x509"
	"fmt"

	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/awsiid/awsrsa1024"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/awsiid/awsrsa2048"
)

// PublicKeyType is the type of public key used to verify the AWS signature.
type PublicKeyType int

const (
	KeyTypeUnset PublicKeyType = iota
	RSA1024
	RSA2048
)

func getAWSCACertificate(region string, keyType PublicKeyType) (*x509.Certificate, error) {
	var cert string
	if keyType == KeyTypeUnset {
		return nil, fmt.Errorf("signature type is unset")
	}

	switch keyType {
	case RSA1024:
		cert = awsrsa1024.CACerts[region]
		if cert == "" {
			// Fall back to the default cert
			cert = awsrsa1024.AWSCACert
		}
	case RSA2048:
		var ok bool
		cert, ok = awsrsa2048.CACerts[region]
		if !ok {
			return nil, fmt.Errorf("unsupported region %q", region)
		}
	}

	ca, err := pemutil.ParseCertificate([]byte(cert))
	if err != nil {
		return nil, err
	}

	return ca, nil
}
