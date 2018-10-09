package bundleutil

import (
	"crypto/x509"
	"fmt"

	"github.com/spiffe/spire/proto/common"
	"github.com/zeebo/errs"
)

func BundleProtoFromRootCAsDER(trustDomainId string, derBytes []byte) (*common.Bundle, error) {
	rootCAs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return BundleProtoFromRootCAs(trustDomainId, rootCAs), nil
}

func BundleProtoFromRootCA(trustDomainId string, rootCA *x509.Certificate) *common.Bundle {
	return BundleProtoFromRootCAs(trustDomainId, []*x509.Certificate{rootCA})
}

func BundleProtoFromRootCAs(trustDomainId string, rootCAs []*x509.Certificate) *common.Bundle {
	b := &common.Bundle{
		TrustDomainId: trustDomainId,
	}
	for _, rootCA := range rootCAs {
		b.RootCas = append(b.RootCas, &common.Certificate{
			DerBytes: rootCA.Raw,
		})
	}
	return b
}

func RootCAsDERFromBundleProto(b *common.Bundle) (derBytes []byte) {
	for _, rootCA := range b.RootCas {
		derBytes = append(derBytes, rootCA.DerBytes...)
	}
	return derBytes
}

func RootCAsFromBundleProto(b *common.Bundle) (out []*x509.Certificate, err error) {
	for i, rootCA := range b.RootCas {
		cert, err := x509.ParseCertificate(rootCA.DerBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse root CA %d: %v", i, err)
		}
		out = append(out, cert)
	}
	return out, nil
}
