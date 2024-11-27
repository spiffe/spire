package keyvaluestore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/protoutil"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/keyvalue"
	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/record"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CreateFederationRelationship creates a new federation relationship. If the bundle endpoint
// profile is 'https_spiffe' and the given federation relationship contains a bundle, the current
// stored bundle is overridden.
// If no bundle is provided and there is not a previously stored bundle in the datastore, the
// federation relationship is not created.
func (ds *DataStore) CreateFederationRelationship(ctx context.Context, in *datastore.FederationRelationship) (*datastore.FederationRelationship, error) {
	if err := validateFederationRelationship(in, protoutil.AllTrueFederationRelationshipMask); err != nil {
		return nil, err
	}
	if err := ds.federationRelationships.Create(ctx, federationRelationshipObject{FederationRelationship: in}); err != nil {
		return nil, dsErr(err, "failed to create federation relationship")
	}

	if in.TrustDomainBundle != nil {
		if _, err := ds.SetBundle(ctx, in.TrustDomainBundle); err != nil {
			//ds.log.WithError(err).Warn("unable to set bundle")
			return nil, fmt.Errorf("unable to set bundle: %w", err)
		}
	}

	return in, nil
}

// FetchFederationRelationship fetches the federation relationship that matches
// the given trust domain. If the federation relationship is not found, nil is returned.
func (ds *DataStore) FetchFederationRelationship(ctx context.Context, td spiffeid.TrustDomain) (*datastore.FederationRelationship, error) {
	if td.IsZero() {
		return nil, status.Error(codes.InvalidArgument, "trust domain is required")
	}
	out, err := ds.federationRelationships.Get(ctx, td.Name())
	switch {
	case err == nil:
		return ds.makeFederationRelationship(ctx, out.Object.FederationRelationship), nil
	case errors.Is(err, record.ErrNotFound):
		return nil, nil
	default:
		return nil, dsErr(err, "failed to fetch federation relationship")
	}
}

// ListFederationRelationships can be used to list all existing federation relationships
func (ds *DataStore) ListFederationRelationships(ctx context.Context, req *datastore.ListFederationRelationshipsRequest) (*datastore.ListFederationRelationshipsResponse, error) {
	records, cursor, err := ds.federationRelationships.List(ctx, req)
	if err != nil {
		return nil, err
	}
	resp := &datastore.ListFederationRelationshipsResponse{
		Pagination: newPagination(req.Pagination, cursor),
	}
	resp.FederationRelationships = make([]*datastore.FederationRelationship, 0, len(records))
	for _, r := range records {
		resp.FederationRelationships = append(resp.FederationRelationships, ds.makeFederationRelationship(ctx, r.Object.FederationRelationship))
	}
	return resp, nil
}

// DeleteFederationRelationship deletes the federation relationship to the
// given trust domain. The associated trust bundle is not deleted.
func (ds *DataStore) DeleteFederationRelationship(ctx context.Context, td spiffeid.TrustDomain) error {
	if td.IsZero() {
		return status.Error(codes.InvalidArgument, "trust domain is required")
	}

	if err := ds.federationRelationships.Delete(ctx, td.Name()); err != nil {
		return dsErr(err, "datastore-keyvalue")
	}
	return nil
}

// UpdateFederationRelationship updates the given federation relationship.
// Attributes are only updated if the correspondent mask value is set to true.
func (ds *DataStore) UpdateFederationRelationship(ctx context.Context, fr *datastore.FederationRelationship, mask *types.FederationRelationshipMask) (*datastore.FederationRelationship, error) {
	if err := validateFederationRelationship(fr, mask); err != nil {
		return nil, err
	}
	existing, err := ds.federationRelationships.Get(ctx, fr.TrustDomain.Name())
	if err != nil {
		return nil, dsErr(err, "unable to fetch federation relationship")
	}

	updated := existing.Object

	// SQL dont verify if mask is equal nil
	/*
		if mask == nil {
			mask = protoutil.AllTrueFederationRelationshipMask
		} */

	if mask.BundleEndpointUrl {
		updated.FederationRelationship.BundleEndpointURL = fr.BundleEndpointURL
	}
	if mask.BundleEndpointProfile {
		updated.FederationRelationship.BundleEndpointProfile = fr.BundleEndpointProfile
		if fr.BundleEndpointProfile == datastore.BundleEndpointSPIFFE {
			updated.FederationRelationship.EndpointSPIFFEID = fr.EndpointSPIFFEID
		}
	}

	if mask.TrustDomainBundle && fr.TrustDomainBundle != nil {
		if _, err := ds.SetBundle(ctx, fr.TrustDomainBundle); err != nil {
			//ds.log.WithError(err).Warn("unable to set bundle")
			return nil, fmt.Errorf("unable to set bundle: %w", err)
		}
	}

	if err := ds.federationRelationships.Update(ctx, updated, existing.Metadata.Revision); err != nil {
		return nil, dsErr(err, "failed to update federation relationship")
	}

	updated.FederationRelationship.TrustDomainBundle, err = ds.FetchBundle(ctx, fr.TrustDomain.IDString())
	if err != nil {
		return nil, dsErr(err, "failed to fetch bundle for federation relationship")
	}

	return updated.FederationRelationship, nil
}

func (ds *DataStore) makeFederationRelationship(ctx context.Context, in *datastore.FederationRelationship) *datastore.FederationRelationship {
	fr := *in
	if bundleRecord, err := ds.bundles.Get(ctx, in.TrustDomain.IDString()); err == nil {
		fr.TrustDomainBundle = bundleRecord.Object.Bundle
	}
	return &fr
}

func validateFederationRelationship(fr *datastore.FederationRelationship, mask *types.FederationRelationshipMask) error {
	if fr == nil {
		return status.Error(codes.InvalidArgument, "federation relationship is nil")
	}

	if fr.TrustDomain.IsZero() {
		return status.Error(codes.InvalidArgument, "trust domain is required")
	}

	if mask.BundleEndpointUrl && fr.BundleEndpointURL == nil {
		return status.Error(codes.InvalidArgument, "bundle endpoint URL is required")
	}

	if mask.BundleEndpointProfile {
		switch fr.BundleEndpointProfile {
		case datastore.BundleEndpointWeb:
		case datastore.BundleEndpointSPIFFE:
			if fr.EndpointSPIFFEID.IsZero() {
				return status.Error(codes.InvalidArgument, "bundle endpoint SPIFFE ID is required")
			}
		default:
			return status.Errorf(codes.InvalidArgument, "unknown bundle endpoint profile type: %q", fr.BundleEndpointProfile)
		}
	}

	return nil
}

type federationRelationshipObject struct {
	FederationRelationship *datastore.FederationRelationship
}

func (o federationRelationshipObject) Key() string {
	if o.FederationRelationship == nil {
		return ""
	}
	return o.FederationRelationship.TrustDomain.Name()
}

type federationRelationshipData struct {
	TrustDomain           string `json:"trust_domain"`
	BundleEndpointURL     string `json:"bundle_endpoint_url"`
	BundleEndpointProfile string `json:"bundle_endpoint_profile"`
	EndpointSPIFFEID      string `json:"endpoint_spiffe_id"`
}

type federationRelationshipCodec struct{}

func (federationRelationshipCodec) Marshal(o *federationRelationshipObject) (string, []byte, error) {
	data, err := json.Marshal(&federationRelationshipData{
		TrustDomain:           o.FederationRelationship.TrustDomain.Name(),
		BundleEndpointURL:     o.FederationRelationship.BundleEndpointURL.String(),
		BundleEndpointProfile: string(o.FederationRelationship.BundleEndpointProfile),
		EndpointSPIFFEID:      o.FederationRelationship.EndpointSPIFFEID.String(),
	})
	if err != nil {
		return "", nil, err
	}
	return o.Key(), data, nil
}

func (federationRelationshipCodec) Unmarshal(in []byte, out *federationRelationshipObject) error {
	frdata := new(federationRelationshipData)
	if err := json.Unmarshal(in, frdata); err != nil {
		return err
	}

	trustDomain, err := spiffeid.TrustDomainFromString(frdata.TrustDomain)
	if err != nil {
		return dsErr(err, "failed to unmarshal federation relationship trust domain")
	}
	bundleEndpointURL, err := url.Parse(frdata.BundleEndpointURL)
	if err != nil {
		return dsErr(err, "failed to unmarshal federation relationship bundle endpoint URL")
	}
	bundleEndpointProfile := datastore.BundleEndpointType(frdata.BundleEndpointProfile)
	if err != nil {
		return dsErr(err, "failed to unmarshal federation relationship bundle endpoint URL")
	}
	var endpointSPIFFEID spiffeid.ID
	if bundleEndpointProfile == datastore.BundleEndpointSPIFFE {
		endpointSPIFFEID, err = spiffeid.FromString(frdata.EndpointSPIFFEID)
		if err != nil {
			return dsErr(err, "failed to unmarshal federation relationship bundle endpoint SPIFFE ID")
		}
	}

	out.FederationRelationship = &datastore.FederationRelationship{
		TrustDomain:           trustDomain,
		BundleEndpointURL:     bundleEndpointURL,
		BundleEndpointProfile: bundleEndpointProfile,
		EndpointSPIFFEID:      endpointSPIFFEID,
	}

	return nil
}

type federationRelationshipIndex struct {
}

func (c *federationRelationshipIndex) SetUp() {
}

func (c *federationRelationshipIndex) Get(obj *record.Record[federationRelationshipObject]) {

}

func (c *federationRelationshipIndex) List(req *datastore.ListFederationRelationshipsRequest) (*keyvalue.ListObject, error) {
	cursor, limit, err := getPaginationParams(req.Pagination)
	if err != nil {
		return nil, err
	}

	list := new(keyvalue.ListObject)

	list.Cursor = cursor
	list.Limit = limit

	return list, nil
}
