package api

import (
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/proto/spire/types"
)

func TrustDomainMemberIDFromProto(td spiffeid.TrustDomain, protoID *types.SPIFFEID) (spiffeid.ID, error) {
	id, err := idFromProto(protoID)
	if err != nil {
		return spiffeid.ID{}, err
	}
	if err := VerifyTrustDomainMemberID(td, id); err != nil {
		return spiffeid.ID{}, err
	}
	return id, nil
}

func VerifyTrustDomainMemberID(td spiffeid.TrustDomain, id spiffeid.ID) error {
	if !id.MemberOf(td) {
		return fmt.Errorf("%q is not a member of trust domain %q", id, td)
	}
	if id.Path() == "" {
		return fmt.Errorf("%q is not a member of trust domain %q; path is empty", id, td)
	}
	return nil
}

func TrustDomainAgentIDFromProto(td spiffeid.TrustDomain, protoID *types.SPIFFEID) (spiffeid.ID, error) {
	id, err := idFromProto(protoID)
	if err != nil {
		return spiffeid.ID{}, err
	}
	if err := VerifyTrustDomainAgentID(td, id); err != nil {
		return spiffeid.ID{}, err
	}
	return id, nil
}

func VerifyTrustDomainAgentID(td spiffeid.TrustDomain, id spiffeid.ID) error {
	if !id.MemberOf(td) {
		return fmt.Errorf("%q is not a member of trust domain %q", id, td)
	}
	if id.Path() == "" {
		return fmt.Errorf("%q is not an agent in trust domain %q; path is empty", id, td)
	}
	if !idutil.IsAgentPath(id.Path()) {
		return fmt.Errorf("%q is not an agent in trust domain %q; path is not in the agent namespace", id, td)
	}
	return nil
}

func TrustDomainWorkloadIDFromProto(td spiffeid.TrustDomain, protoID *types.SPIFFEID) (spiffeid.ID, error) {
	id, err := idFromProto(protoID)
	if err != nil {
		return spiffeid.ID{}, err
	}
	if err := VerifyTrustDomainWorkloadID(td, id); err != nil {
		return spiffeid.ID{}, err
	}
	return id, nil
}

func VerifyTrustDomainWorkloadID(td spiffeid.TrustDomain, id spiffeid.ID) error {
	if !id.MemberOf(td) {
		return fmt.Errorf("%q is not a member of trust domain %q", id, td)
	}
	if id.Path() == "" {
		return fmt.Errorf("%q is not a workload in trust domain %q; path is empty", id, td)
	}
	if idutil.IsReservedPath(id.Path()) {
		return fmt.Errorf("%q is not a workload in trust domain %q; path is in the reserved namespace", id, td)
	}
	return nil
}

// ProtoFromID converts a SPIFFE ID from the given spiffeid.ID to
// types.SPIFFEID
func ProtoFromID(id spiffeid.ID) *types.SPIFFEID {
	return &types.SPIFFEID{
		TrustDomain: id.TrustDomain().String(),
		Path:        id.Path(),
	}
}

func idFromProto(protoID *types.SPIFFEID) (spiffeid.ID, error) {
	if protoID == nil {
		return spiffeid.ID{}, errors.New("request must specify SPIFFE ID")
	}
	return idutil.IDFromProto(protoID)
}
