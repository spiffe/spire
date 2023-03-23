package bundle

import (
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/pkg/common/coretypes/jwtkey"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/proto/spire/common"
)

func ToCommonFromPluginProto(pb *plugintypes.Bundle) (*common.Bundle, error) {
	if pb == nil {
		return nil, nil
	}
	jwtSigningKeys, err := jwtkey.ToCommonFromPluginProtos(pb.JwtAuthorities)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT authority: %w", err)
	}

	rootCAs, err := x509certificate.ToCommonFromPluginProtos(pb.X509Authorities)
	if err != nil {
		return nil, fmt.Errorf("invalid X.509 authority: %w", err)
	}

	td, err := spiffeid.TrustDomainFromString(pb.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("malformed trust domain: %w", err)
	}

	return &common.Bundle{
		TrustDomainId:  td.IDString(),
		RefreshHint:    pb.RefreshHint,
		JwtSigningKeys: jwtSigningKeys,
		RootCas:        rootCAs,
	}, nil
}

func ToPluginProtoFromCommon(b *common.Bundle) (*plugintypes.Bundle, error) {
	td, err := spiffeid.TrustDomainFromString(b.TrustDomainId)
	if err != nil {
		return nil, err
	}
	return &plugintypes.Bundle{
		TrustDomain:     td.String(),
		RefreshHint:     b.RefreshHint,
		SequenceNumber:  0,
		X509Authorities: certificatesToProto(b.RootCas),
		JwtAuthorities:  publicKeysToProto(b.JwtSigningKeys),
	}, nil
}

func certificatesToProto(rootCas []*common.Certificate) []*plugintypes.X509Certificate {
	var x509Authorities []*plugintypes.X509Certificate
	for _, rootCA := range rootCas {
		x509Authorities = append(x509Authorities, &plugintypes.X509Certificate{
			Asn1: rootCA.DerBytes,
		})
	}

	return x509Authorities
}

func publicKeysToProto(keys []*common.PublicKey) []*plugintypes.JWTKey {
	var jwtAuthorities []*plugintypes.JWTKey
	for _, key := range keys {
		jwtAuthorities = append(jwtAuthorities, &plugintypes.JWTKey{
			PublicKey: key.PkixBytes,
			KeyId:     key.Kid,
			ExpiresAt: key.NotAfter,
		})
	}
	return jwtAuthorities
}
