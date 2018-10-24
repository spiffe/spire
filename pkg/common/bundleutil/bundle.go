package bundleutil

import (
	"crypto/x509"
	"fmt"

	"github.com/golang/protobuf/proto"
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

func MergeBundles(a, b *common.Bundle) (*common.Bundle, bool) {
	c := cloneBundle(a)

	rootCAs := make(map[string]bool)
	for _, rootCA := range a.RootCas {
		rootCAs[rootCA.String()] = true
	}
	jwtSigningKeys := make(map[string]bool)
	for _, jwtSigningKey := range a.JwtSigningKeys {
		jwtSigningKeys[jwtSigningKey.String()] = true
	}

	var changed bool
	for _, rootCA := range b.RootCas {
		if !rootCAs[rootCA.String()] {
			c.RootCas = append(c.RootCas, rootCA)
			changed = true
		}
	}
	for _, jwtSigningKey := range b.JwtSigningKeys {
		if !jwtSigningKeys[jwtSigningKey.String()] {
			c.JwtSigningKeys = append(c.JwtSigningKeys, jwtSigningKey)
			changed = true
		}
	}
	return c, changed
}

func cloneBundle(b *common.Bundle) *common.Bundle {
	return proto.Clone(b).(*common.Bundle)
}
