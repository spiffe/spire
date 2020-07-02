package api

import (
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
)

// RegistrationEntriesToProto converts RegistrationEntry's into Entry's
func RegistrationEntriesToProto(es []*common.RegistrationEntry) ([]*types.Entry, error) {
	if es == nil {
		return nil, nil
	}
	pbs := make([]*types.Entry, 0, len(es))
	for _, e := range es {
		pb, err := RegistrationEntryToProto(e)
		if err != nil {
			return nil, err
		}
		pbs = append(pbs, pb)
	}
	return pbs, nil
}

// RegistrationEntryToProto converts RegistrationEntry into Entry
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

// ProtoToRegistrationEntry converts and validate entry into common registration entry
func ProtoToRegistrationEntry(e *types.Entry) (*common.RegistrationEntry, error) {
	if e == nil {
		return nil, errors.New("missing entry")
	}

	parentID, err := IDFromProto(e.ParentId)
	if err != nil {
		return nil, fmt.Errorf("invalid parent ID: %v", err)
	}

	spiffeID, err := IDFromProto(e.SpiffeId)
	if err != nil {
		return nil, fmt.Errorf("invalid spiffe ID: %v", err)
	}

	for _, dnsName := range e.DnsNames {
		if err := x509util.ValidateDNS(dnsName); err != nil {
			return nil, fmt.Errorf("invalid DNS name: %v", err)
		}
	}

	// Validate and normalize TDs
	for i, federatedWith := range e.FederatesWith {
		td, err := spiffeid.TrustDomainFromString(federatedWith)
		if err != nil {
			return nil, fmt.Errorf("invalid federated trust domain: %v", err)
		}
		e.FederatesWith[i] = td.IDString()
	}

	selectors, err := SelectorsFromProto(e.Selectors)
	if err != nil {
		return nil, err
	}

	return &common.RegistrationEntry{
		EntryId:       e.Id,
		ParentId:      parentID.String(),
		SpiffeId:      spiffeID.String(),
		Admin:         e.Admin,
		DnsNames:      e.DnsNames,
		Downstream:    e.Downstream,
		EntryExpiry:   e.ExpiresAt,
		FederatesWith: e.FederatesWith,
		Selectors:     selectors,
		Ttl:           e.Ttl,
	}, nil
}
