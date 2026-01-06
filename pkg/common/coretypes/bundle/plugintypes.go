package bundle

import (
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	apitypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/pkg/common/coretypes/jwtkey"
	"github.com/spiffe/spire/pkg/common/coretypes/witkey"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/proto/spire/common"
)

func ToPluginFromAPIProto(pb *apitypes.Bundle) (*plugintypes.Bundle, error) {
	if pb == nil {
		return nil, nil
	}
	jwtAuthorities, err := jwtkey.ToPluginFromAPIProtos(pb.JwtAuthorities)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT authority: %w", err)
	}

	x509Authorities, err := x509certificate.ToPluginFromAPIProtos(pb.X509Authorities)
	if err != nil {
		return nil, fmt.Errorf("invalid X.509 authority: %w", err)
	}

	witAuthorities, err := witkey.ToPluginFromAPIProtos(pb.WitAuthorities)
	if err != nil {
		return nil, fmt.Errorf("invalid WIT authority: %w", err)
	}

	td, err := spiffeid.TrustDomainFromString(pb.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("malformed trust domain: %w", err)
	}

	return &plugintypes.Bundle{
		TrustDomain:     td.Name(),
		RefreshHint:     pb.RefreshHint,
		SequenceNumber:  pb.SequenceNumber,
		JwtAuthorities:  jwtAuthorities,
		X509Authorities: x509Authorities,
		WitAuthorities:  witAuthorities,
	}, nil
}

func ToPluginProtoFromCommon(b *common.Bundle) (*plugintypes.Bundle, error) {
	if b == nil {
		return nil, nil
	}

	td, err := spiffeid.TrustDomainFromString(b.TrustDomainId)
	if err != nil {
		return nil, err
	}

	x509Authorities, err := x509certificate.ToPluginFromCommonProtos(b.RootCas)
	if err != nil {
		return nil, fmt.Errorf("invalid X.509 authority: %w", err)
	}

	jwtAuthorities, err := jwtkey.ToPluginFromCommonProtos(b.JwtSigningKeys)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT authority: %w", err)
	}

	witAuthorities, err := witkey.ToPluginFromCommonProtos(b.WitSigningKeys)
	if err != nil {
		return nil, fmt.Errorf("invalid WIT authority: %w", err)
	}

	return &plugintypes.Bundle{
		TrustDomain:     td.Name(),
		RefreshHint:     b.RefreshHint,
		SequenceNumber:  b.SequenceNumber,
		X509Authorities: x509Authorities,
		JwtAuthorities:  jwtAuthorities,
		WitAuthorities:  witAuthorities,
	}, nil
}
