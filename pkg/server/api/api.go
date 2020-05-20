package api

import (
	"errors"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/proto/spire-next/types"
)

// IDFromProto converts a SPIFFE ID from the given
// types.SPIFFEID to spiffeid.ID
func IDFromProto(protoID *types.SPIFFEID) (spiffeid.ID, error) {
	if protoID == nil {
		return spiffeid.ID{}, errors.New("request must specify SPIFFE ID")
	}
	return spiffeid.New(protoID.TrustDomain, protoID.Path)
}
