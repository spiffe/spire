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
		SequenceNumber: pb.SequenceNumber,
		JwtSigningKeys: jwtSigningKeys,
		RootCas:        rootCAs,
	}, nil
}
