package api

import (
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/proto/spire-next/types"
)

func SpiffeIDToProto(id spiffeid.ID) *types.SPIFFEID {
	return &types.SPIFFEID{
		TrustDomain: id.TrustDomain().String(),
		Path:        id.Path(),
	}
}

func SpiffeIDFromProto(id *types.SPIFFEID) (spiffeid.ID, error) {
	return spiffeid.New(id.TrustDomain, id.Path)
}
