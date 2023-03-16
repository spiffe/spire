package api

import (
	"context"
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/protoutil"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
)

const (
	hintMaximumLength = 1024
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

	var federatesWith []string
	if len(e.FederatesWith) > 0 {
		federatesWith = make([]string, 0, len(e.FederatesWith))
		for _, trustDomainID := range e.FederatesWith {
			td, err := spiffeid.TrustDomainFromString(trustDomainID)
			if err != nil {
				return nil, fmt.Errorf("invalid federated trust domain: %w", err)
			}
			federatesWith = append(federatesWith, td.String())
		}
	}

	return &types.Entry{
		Id:             e.EntryId,
		SpiffeId:       ProtoFromID(spiffeID),
		ParentId:       ProtoFromID(parentID),
		Selectors:      ProtoFromSelectors(e.Selectors),
		X509SvidTtl:    e.X509SvidTtl,
		FederatesWith:  federatesWith,
		Admin:          e.Admin,
		Downstream:     e.Downstream,
		ExpiresAt:      e.EntryExpiry,
		DnsNames:       append([]string(nil), e.DnsNames...),
		RevisionNumber: e.RevisionNumber,
		StoreSvid:      e.StoreSvid,
		JwtSvidTtl:     e.JwtSvidTtl,
		Hint:           e.Hint,
		CreatedAt:      e.CreatedAt,
	}, nil
}

// ProtoToRegistrationEntry converts and validate entry into common registration entry
func ProtoToRegistrationEntry(ctx context.Context, td spiffeid.TrustDomain, e *types.Entry) (*common.RegistrationEntry, error) {
	return ProtoToRegistrationEntryWithMask(ctx, td, e, nil)
}

// ProtoToRegistrationEntryWithMask converts and validate entry into common registration entry,
// while allowing empty values for SpiffeId, ParentId, and Selectors IF their corresponding values
// in the mask are false.
// This allows the user to not specify these fields while updating using a mask.
// All other fields are allowed to be empty (with or without a mask).
func ProtoToRegistrationEntryWithMask(ctx context.Context, td spiffeid.TrustDomain, e *types.Entry, mask *types.EntryMask) (_ *common.RegistrationEntry, err error) {
	if e == nil {
		return nil, errors.New("missing entry")
	}

	if mask == nil {
		mask = protoutil.AllTrueEntryMask
	}

	var parentID spiffeid.ID
	if mask.ParentId {
		parentID, err = TrustDomainMemberIDFromProto(ctx, td, e.ParentId)
		if err != nil {
			return nil, fmt.Errorf("invalid parent ID: %w", err)
		}
	}

	var spiffeID spiffeid.ID
	if mask.SpiffeId {
		spiffeID, err = TrustDomainWorkloadIDFromProto(ctx, td, e.SpiffeId)
		if err != nil {
			return nil, fmt.Errorf("invalid spiffe ID: %w", err)
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
	if mask.Selectors {
		if len(e.Selectors) == 0 {
			return nil, errors.New("selector list is empty")
		}
		selectors, err = SelectorsFromProto(e.Selectors)
		if err != nil {
			return nil, err
		}
	}

	var revisionNumber int64
	if mask.RevisionNumber {
		revisionNumber = e.RevisionNumber
	}

	var storeSVID bool
	if mask.StoreSvid {
		storeSVID = e.StoreSvid
	}

	var x509SvidTTL int32
	if mask.X509SvidTtl {
		x509SvidTTL = e.X509SvidTtl
	}

	var jwtSvidTTL int32
	if mask.JwtSvidTtl {
		jwtSvidTTL = e.JwtSvidTtl
	}

	var hint string
	if mask.Hint {
		if len(e.Hint) > hintMaximumLength {
			return nil, fmt.Errorf("hint is too long, max length is %d characters", hintMaximumLength)
		}
		hint = e.Hint
	}
	return &common.RegistrationEntry{
		EntryId:        e.Id,
		ParentId:       parentID.String(),
		SpiffeId:       spiffeID.String(),
		Admin:          admin,
		DnsNames:       dnsNames,
		Downstream:     downstream,
		EntryExpiry:    expiresAt,
		FederatesWith:  federatesWith,
		Selectors:      selectors,
		RevisionNumber: revisionNumber,
		StoreSvid:      storeSVID,
		X509SvidTtl:    x509SvidTTL,
		JwtSvidTtl:     jwtSvidTTL,
		Hint:           hint,
	}, nil
}
