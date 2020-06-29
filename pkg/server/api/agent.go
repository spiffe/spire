package api

import (
	"errors"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
)

func ProtoFromAttestedNode(n *common.AttestedNode) (*types.Agent, error) {
	if n == nil {
		return nil, errors.New("missing attested node")
	}

	spiffeID, err := spiffeid.FromString(n.SpiffeId)
	if err != nil {
		return nil, err
	}

	var selectors []*types.Selector
	for _, s := range n.Selectors {
		selectors = append(selectors, &types.Selector{
			Type:  s.Type,
			Value: s.Value,
		})
	}

	return &types.Agent{
		AttestationType:      n.AttestationDataType,
		Id:                   ProtoFromID(spiffeID),
		X509SvidExpiresAt:    n.CertNotAfter,
		X509SvidSerialNumber: n.CertSerialNumber,
		Banned:               n.CertSerialNumber == "",
		Selectors:            selectors,
	}, nil
}
