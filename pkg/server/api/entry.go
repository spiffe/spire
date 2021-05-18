package api

import (
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/protoutil"
	"github.com/spiffe/spire/pkg/common/x509util"
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

// RegistrationEntryToProto converts RegistrationEntry into types Entry
func RegistrationEntryToProto(e *common.RegistrationEntry) (*types.Entry, error) {
	if e == nil {
		return nil, errors.New("missing registration entry")
	}

	spiffeID, err := spiffeid.FromString(e.SpiffeId)
	if err != nil {
		return nil, fmt.Errorf("invalid SPIFFE ID: %w", err)
	}

	parentID, err := spiffeid.FromString(e.ParentId)
	if err != nil {
		return nil, fmt.Errorf("invalid parent ID: %w", err)
	}

	federatesWith := make([]string, 0, len(e.FederatesWith))
	for _, trustDomainID := range e.FederatesWith {
		td, err := spiffeid.TrustDomainFromString(trustDomainID)
		if err != nil {
			return nil, fmt.Errorf("invalid federated trust domain: %w", err)
		}
		federatesWith = append(federatesWith, td.String())
	}

	return &types.Entry{
		Id:             e.EntryId,
		SpiffeId:       ProtoFromID(spiffeID),
		ParentId:       ProtoFromID(parentID),
		Selectors:      ProtoFromSelectors(e.Selectors),
		Ttl:            e.Ttl,
		FederatesWith:  federatesWith,
		Admin:          e.Admin,
		Downstream:     e.Downstream,
		ExpiresAt:      e.EntryExpiry,
		DnsNames:       append([]string(nil), e.DnsNames...),
		RevisionNumber: e.RevisionNumber,
	}, nil
}

// ProtoToRegistrationEntry converts and validate entry into common registration entry
func ProtoToRegistrationEntry(td spiffeid.TrustDomain, e *types.Entry) (*common.RegistrationEntry, error) {
	return ProtoToRegistrationEntryWithMask(td, e, nil)
}

// ProtoToRegistrationEntryWithMask converts and validate entry into common registration entry,
// while allowing empty values for SpiffeId, ParentId, and Selectors IF their corresponding values
// in the mask are false.
// This allows the user to not specify these fields while updating using a mask.
// All other fields are allowed to be empty (with or without a mask).
func ProtoToRegistrationEntryWithMask(td spiffeid.TrustDomain, e *types.Entry, mask *types.EntryMask) (*common.RegistrationEntry, error) {
	if e == nil {
		return nil, errors.New("missing entry")
	}

	if mask == nil {
		mask = protoutil.AllTrueEntryMask
	}

	var parentIDString string
	if mask.ParentId {
		parentID, err := TrustDomainMemberIDFromProto(td, e.ParentId)
		if err != nil {
			return nil, fmt.Errorf("invalid parent ID: %w", err)
		}
		parentIDString = parentID.String()
		if err := idutil.CheckIDProtoNormalization(e.ParentId); err != nil {
			return nil, fmt.Errorf("parent ID is malformed: %w", err)
		}
	}

	var spiffeIDString string
	if mask.SpiffeId {
		spiffeID, err := TrustDomainWorkloadIDFromProto(td, e.SpiffeId)
		if err != nil {
			return nil, fmt.Errorf("invalid spiffe ID: %w", err)
		}
		spiffeIDString = spiffeID.String()
		if err := idutil.CheckIDProtoNormalization(e.SpiffeId); err != nil {
			return nil, fmt.Errorf("spiffe ID is malformed: %w", err)
		}
	}

	var admin bool
	if mask.Admin {
		admin = e.Admin
	}

	var dnsNames []string
	if mask.DnsNames {
		dnsNames = make([]string, 0, len(e.DnsNames))
		for _, dnsName := range e.DnsNames {
			if err := x509util.ValidateDNS(dnsName); err != nil {
				return nil, fmt.Errorf("invalid DNS name: %w", err)
			}
			dnsNames = append(dnsNames, dnsName)
		}
	}

	var downstream bool
	if mask.Downstream {
		downstream = e.Downstream
	}

	var expiresAt int64
	if mask.ExpiresAt {
		expiresAt = e.ExpiresAt
	}

	var federatesWith []string
	if mask.FederatesWith {
		federatesWith = make([]string, 0, len(e.FederatesWith))
		for _, trustDomainName := range e.FederatesWith {
			td, err := spiffeid.TrustDomainFromString(trustDomainName)
			if err != nil {
				return nil, fmt.Errorf("invalid federated trust domain: %w", err)
			}
			federatesWith = append(federatesWith, td.IDString())
		}
	}

	var selectors []*common.Selector
	var err error
	if mask.Selectors {
		if len(e.Selectors) == 0 {
			return nil, errors.New("selector list is empty")
		}
		selectors, err = SelectorsFromProto(e.Selectors)
		if err != nil {
			return nil, err
		}
	}

	var ttl int32
	if mask.Ttl {
		ttl = e.Ttl
	}

	var revisionNumber int64
	if mask.RevisionNumber {
		revisionNumber = e.RevisionNumber
	}

	return &common.RegistrationEntry{
		EntryId:        e.Id,
		ParentId:       parentIDString,
		SpiffeId:       spiffeIDString,
		Admin:          admin,
		DnsNames:       dnsNames,
		Downstream:     downstream,
		EntryExpiry:    expiresAt,
		FederatesWith:  federatesWith,
		Selectors:      selectors,
		Ttl:            ttl,
		RevisionNumber: revisionNumber,
	}, nil
}
