package bundle

import (
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	apitypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/spiffe/spire/pkg/common/coretypes/jwtkey"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
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

	td, err := spiffeid.TrustDomainFromString(pb.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("malformed trust domain: %w", err)
	}

	return &plugintypes.Bundle{
		TrustDomain:     td.String(),
		RefreshHint:     pb.RefreshHint,
		SequenceNumber:  pb.SequenceNumber,
		JwtAuthorities:  jwtAuthorities,
		X509Authorities: x509Authorities,
	}, nil
}
