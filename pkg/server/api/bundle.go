package api

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
)

func BundleToProto(b *common.Bundle) (*types.Bundle, error) {
	if b == nil {
		return nil, errors.New("no bundle provided")
	}

	td, err := spiffeid.TrustDomainFromString(b.TrustDomainId)
	if err != nil {
		return nil, err
	}
	var x509Authorities []*types.X509Certificate
	for _, rootCA := range b.RootCas {
		x509Authorities = append(x509Authorities, &types.X509Certificate{
			Asn1: rootCA.DerBytes,
		})
	}

	var jwtAuthorities []*types.JWTKey
	for _, key := range b.JwtSigningKeys {
		jwtAuthorities = append(jwtAuthorities, &types.JWTKey{
			PublicKey: key.PkixBytes,
			KeyId:     key.Kid,
			ExpiresAt: key.NotAfter,
		})
	}
	return &types.Bundle{
		TrustDomain:     td.String(),
		RefreshHint:     b.RefreshHint,
		SequenceNumber:  0,
		X509Authorities: x509Authorities,
		JwtAuthorities:  jwtAuthorities,
	}, nil
}

func ProtoToBundle(b *types.Bundle) (*common.Bundle, error) {
	if b == nil {
		return nil, errors.New("no bundle provided")
	}

	td, err := spiffeid.TrustDomainFromString(b.TrustDomain)
	if err != nil {
		return nil, err
	}

	rootCas, err := parseX509Authorities(b.X509Authorities)
	if err != nil {
		return nil, fmt.Errorf("unable to parse X.509 authority: %v", err)
	}

	jwtSigningKeys, err := parseJWTAuthorities(b.JwtAuthorities)
	if err != nil {
		return nil, fmt.Errorf("unable to parse JWT authority: %v", err)
	}

	commonBundle := &common.Bundle{
		TrustDomainId:  td.IDString(),
		RefreshHint:    b.RefreshHint,
		RootCas:        rootCas,
		JwtSigningKeys: jwtSigningKeys,
	}

	return commonBundle, nil
}

func parseX509Authorities(certs []*types.X509Certificate) ([]*common.Certificate, error) {
	var rootCAs []*common.Certificate
	for _, rootCA := range certs {
		if _, err := x509.ParseCertificates(rootCA.Asn1); err != nil {
			return nil, err
		}

		rootCAs = append(rootCAs, &common.Certificate{
			DerBytes: rootCA.Asn1,
		})
	}

	return rootCAs, nil
}

func parseJWTAuthorities(keys []*types.JWTKey) ([]*common.PublicKey, error) {
	var jwtKeys []*common.PublicKey
	for _, key := range keys {
		if _, err := x509.ParsePKIXPublicKey(key.PublicKey); err != nil {
			return nil, err
		}

		if key.KeyId == "" {
			return nil, errors.New("missing key ID")
		}

		jwtKeys = append(jwtKeys, &common.PublicKey{
			PkixBytes: key.PublicKey,
			Kid:       key.KeyId,
			NotAfter:  key.ExpiresAt,
		})
	}

	return jwtKeys, nil
}
