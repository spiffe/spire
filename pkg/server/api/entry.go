package api

import (
	"errors"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
)

// RegistrationEntryToProto converts RegistrationEntry into types Entry
func RegistrationEntryToProto(e *common.RegistrationEntry) (*types.Entry, error) {
	if e == nil {
		return nil, errors.New("missing registration entry")
	}

	spiffeID, err := spiffeid.FromString(e.SpiffeId)
	if err != nil {
		return nil, err
	}

	parentID, err := spiffeid.FromString(e.ParentId)
	if err != nil {
		return nil, err
	}

	var selectors []*types.Selector
	for _, s := range e.Selectors {
		selectors = append(selectors, &types.Selector{
			Type:  s.Type,
			Value: s.Value,
		})
	}

	return &types.Entry{
		Id:            e.EntryId,
		SpiffeId:      ProtoFromID(spiffeID),
		ParentId:      ProtoFromID(parentID),
		Selectors:     selectors,
		Ttl:           e.Ttl,
		FederatesWith: e.FederatesWith,
		Admin:         e.Admin,
		Downstream:    e.Downstream,
		ExpiresAt:     e.EntryExpiry,
		DnsNames:      e.DnsNames,
	}, nil
}
