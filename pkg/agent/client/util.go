package client

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/proto/spire/common"
)

func spiffeIDFromProto(protoID *types.SPIFFEID) (string, error) {
	if protoID == nil {
		return "", errors.New("request must specify SPIFFE ID")
	}

	td, err := spiffeid.TrustDomainFromString(protoID.TrustDomain)
	if err != nil {
		return "", err
	}

	id, err := spiffeid.FromPath(td, protoID.Path)
	if err != nil {
		return "", err
	}

	return id.String(), nil
}

func slicedEntryFromProto(e *types.Entry) (*common.RegistrationEntry, error) {
	if e == nil {
		return nil, errors.New("missing entry")
	}

	if e.Id == "" {
		return nil, fmt.Errorf("missing entry ID")
	}

	spiffeID, err := spiffeIDFromProto(e.SpiffeId)
	if err != nil {
		return nil, fmt.Errorf("invalid SPIFFE ID: %w", err)
	}

	var federatesWith []string
	for _, trustDomainName := range e.FederatesWith {
		td, err := spiffeid.TrustDomainFromString(trustDomainName)
		if err != nil {
			return nil, fmt.Errorf("invalid federated trust domain: %w", err)
		}
		federatesWith = append(federatesWith, td.IDString())
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
		SpiffeId:       spiffeID,
		FederatesWith:  federatesWith,
		RevisionNumber: e.RevisionNumber,
		Selectors:      selectors,
		StoreSvid:      e.StoreSvid,
		Admin:          e.Admin,
		Downstream:     e.Downstream,
	}, nil
}
