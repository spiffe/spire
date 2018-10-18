package bundleutil

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/spiffe/spire/proto/common"
	"github.com/zeebo/errs"
)

type Bundle struct {
	b              *common.Bundle
	rootCAs        []*x509.Certificate
	jwtSigningKeys map[string]crypto.PublicKey
}

func New(trustDomainID string) *Bundle {
	return &Bundle{
		b: &common.Bundle{
			TrustDomainId: trustDomainID,
		},
	}
}

func ParseBundle(bundleBytes []byte) (*Bundle, error) {
	b := new(common.Bundle)
	if err := proto.Unmarshal(bundleBytes, b); err != nil {
		return nil, errs.New("unable to unmarshal bundle: %v", err)
	}
	return BundleFromProto(b)
}

func BundleFromProto(b *common.Bundle) (*Bundle, error) {
	rootCAs, err := RootCAsFromBundleProto(b)
	if err != nil {
		return nil, err
	}
	jwtSigningKeys, err := JWTSigningKeysFromBundleProto(b)
	if err != nil {
		return nil, err
	}
	return &Bundle{
		b:              b,
		rootCAs:        rootCAs,
		jwtSigningKeys: jwtSigningKeys,
	}, nil
}

func BundleFromRootCA(trustDomainID string, rootCA *x509.Certificate) *Bundle {
	return bundleFromRootCAs(trustDomainID, rootCA)
}

func BundleFromRootCAs(trustDomainID string, rootCAs []*x509.Certificate) *Bundle {
	return bundleFromRootCAs(trustDomainID, rootCAs...)
}

func bundleFromRootCAs(trustDomainID string, rootCAs ...*x509.Certificate) *Bundle {
	b := New(trustDomainID)
	for _, rootCA := range rootCAs {
		b.AppendRootCA(rootCA)
	}
	return b
}

func (b *Bundle) Proto() *common.Bundle {
	return cloneBundle(b.b)
}

func (b *Bundle) TrustDomainID() string {
	return b.b.TrustDomainId
}

func (b *Bundle) EqualTo(other *Bundle) bool {
	return proto.Equal(b.b, other.b)
}

func (b *Bundle) RootCAs() []*x509.Certificate {
	return b.rootCAs
}

func (b *Bundle) JWTSigningKeys() map[string]crypto.PublicKey {
	return b.jwtSigningKeys
}

func (b *Bundle) AppendRootCA(rootCA *x509.Certificate) {
	b.b.RootCas = append(b.b.RootCas, &common.Certificate{
		DerBytes: rootCA.Raw,
	})
	b.rootCAs = append(b.rootCAs, rootCA)

}

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

func JWTSigningKeysFromBundleProto(b *common.Bundle) (map[string]crypto.PublicKey, error) {
	out := make(map[string]crypto.PublicKey)
	for i, publicKey := range b.JwtSigningKeys {
		jwtSigningKey, err := x509.ParsePKIXPublicKey(publicKey.PkixBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse JWT signing key %d: %v", i, err)
		}
		out[publicKey.Kid] = jwtSigningKey
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
