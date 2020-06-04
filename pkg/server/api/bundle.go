package api

import (
	"errors"

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
