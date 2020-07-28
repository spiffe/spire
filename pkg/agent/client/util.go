package client

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/types"
)

func spiffeIDFromProto(protoID *types.SPIFFEID) (string, error) {
	if protoID == nil {
		return "", errors.New("request must specify SPIFFE ID")
	}

	id, err := spiffeid.New(protoID.TrustDomain, protoID.Path)
	if err != nil {
		return "", err
	}

	return id.String(), nil
}

func registrationEntryFromProto(e *types.Entry) (*common.RegistrationEntry, error) {
	if e == nil {
		return nil, errors.New("missing entry")
	}

	if e.Id == "" {
		return nil, fmt.Errorf("missing entry ID")
	}
	parentID, err := spiffeIDFromProto(e.ParentId)
	if err != nil {
		return nil, fmt.Errorf("invalid parent ID: %v", err)
	}

	spiffeID, err := spiffeIDFromProto(e.SpiffeId)
	if err != nil {
		return nil, fmt.Errorf("invalid SPIFFE ID: %v", err)
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

	if len(e.Selectors) == 0 {
		return nil, errors.New("selector list is empty")
	}
	var selectors []*common.Selector
	for _, s := range e.Selectors {
		switch {
		case s.Type == "":
			return nil, errors.New("missing selector type")
		case strings.Contains(s.Type, ":"):
			return nil, errors.New("selector type contains ':'")
		case s.Value == "":
			return nil, errors.New("missing selector value")
		}

		selectors = append(selectors, &common.Selector{
			Type:  s.Type,
			Value: s.Value,
		})
	}

	return &common.RegistrationEntry{
		EntryId:        e.Id,
		ParentId:       parentID,
		SpiffeId:       spiffeID,
		Admin:          e.Admin,
		DnsNames:       e.DnsNames,
		Downstream:     e.Downstream,
		EntryExpiry:    e.ExpiresAt,
		FederatesWith:  e.FederatesWith,
		RevisionNumber: e.RevisionNumber,
		Selectors:      selectors,
		Ttl:            e.Ttl,
	}, nil
}
