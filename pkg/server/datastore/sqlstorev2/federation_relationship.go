package sqlstorev2

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/protoutil"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

// CreateFederationRelationship creates a new federation relationship. If the bundle endpoint
// profile is 'https_spiffe' and the given federation relationship contains a bundle, the current
// stored bundle is overridden.
// If no bundle is provided and there is not a previously stored bundle in the datastore, the
// federation relationship is not created.
func (ds *Plugin) CreateFederationRelationship(ctx context.Context, fr *datastore.FederationRelationship) (newFr *datastore.FederationRelationship, err error) {
	if err := validateFederationRelationship(fr, protoutil.AllTrueFederationRelationshipMask); err != nil {
		return nil, err
	}

	if err := ds.withWriteTx(ctx, func(tx *gorm.DB) error {
		newFr, err = createFederationRelationship(tx, fr)
		return err
	}); err != nil {
		return nil, err
	}
	return newFr, nil
}

// DeleteFederationRelationship deletes the federation relationship to the
// given trust domain. The associated trust bundle is not deleted.
func (ds *Plugin) DeleteFederationRelationship(ctx context.Context, trustDomain spiffeid.TrustDomain) error {
	if trustDomain.IsZero() {
		return status.Error(codes.InvalidArgument, "trust domain is required")
	}

	return ds.withWriteTx(ctx, func(tx *gorm.DB) (err error) {
		err = deleteFederationRelationship(tx, trustDomain)
		return err
	})
}

// FetchFederationRelationship fetches the federation relationship that matches
// the given trust domain. If the federation relationship is not found, nil is returned.
func (ds *Plugin) FetchFederationRelationship(ctx context.Context, trustDomain spiffeid.TrustDomain) (fr *datastore.FederationRelationship, err error) {
	if trustDomain.IsZero() {
		return nil, status.Error(codes.InvalidArgument, "trust domain is required")
	}

	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		fr, err = fetchFederationRelationship(tx, trustDomain)
		return err
	}); err != nil {
		return nil, err
	}

	return fr, nil
}

// ListFederationRelationships can be used to list all existing federation relationships
func (ds *Plugin) ListFederationRelationships(ctx context.Context, req *datastore.ListFederationRelationshipsRequest) (resp *datastore.ListFederationRelationshipsResponse, err error) {
	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		resp, err = listFederationRelationships(tx, req, ds.DatabaseType())
		return err
	}); err != nil {
		return nil, err
	}
	return resp, nil
}

// UpdateFederationRelationship updates the given federation relationship.
// Attributes are only updated if the correspondent mask value is set to true.
func (ds *Plugin) UpdateFederationRelationship(ctx context.Context, fr *datastore.FederationRelationship, mask *types.FederationRelationshipMask) (newFr *datastore.FederationRelationship, err error) {
	if err := validateFederationRelationship(fr, mask); err != nil {
		return nil, err
	}

	if err := ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) error {
		newFr, err = updateFederationRelationship(tx, fr, mask)
		return err
	}); err != nil {
		return nil, err
	}
	return newFr, nil
}

func createFederationRelationship(tx *gorm.DB, fr *datastore.FederationRelationship) (*datastore.FederationRelationship, error) {
	model := FederatedTrustDomain{
		TrustDomain:           fr.TrustDomain.Name(),
		BundleEndpointURL:     fr.BundleEndpointURL.String(),
		BundleEndpointProfile: string(fr.BundleEndpointProfile),
	}

	if fr.BundleEndpointProfile == datastore.BundleEndpointSPIFFE {
		model.EndpointSPIFFEID = fr.EndpointSPIFFEID.String()
	}

	if fr.TrustDomainBundle != nil {
		// overwrite current bundle
		_, err := setBundle(tx, fr.TrustDomainBundle)
		if err != nil {
			return nil, fmt.Errorf("unable to set bundle: %w", err)
		}
	}

	if err := tx.Create(&model).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	return fr, nil
}

func deleteFederationRelationship(tx *gorm.DB, trustDomain spiffeid.TrustDomain) error {
	model := new(FederatedTrustDomain)
	if err := tx.Where("trust_domain = ?", trustDomain.Name()).Take(model).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}
	if err := tx.Delete(model).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}
	return nil
}

func fetchFederationRelationship(tx *gorm.DB, trustDomain spiffeid.TrustDomain) (*datastore.FederationRelationship, error) {
	var model FederatedTrustDomain
	err := tx.Where("trust_domain = ?", trustDomain.Name()).Take(&model).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, nil
	case err != nil:
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	return modelToFederationRelationship(tx, &model)
}

// listFederationRelationships can be used to fetch all existing federation relationships.
func listFederationRelationships(tx *gorm.DB, req *datastore.ListFederationRelationshipsRequest, dbType string) (*datastore.ListFederationRelationshipsResponse, error) {
	if req.Pagination != nil && req.Pagination.PageSize == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot paginate with pagesize = 0")
	}

	// Pagination conditions live on query only; tx is reused to fetch bundles.
	query := tx
	p := req.Pagination
	var err error
	if p != nil {
		query, err = applyPagination(p, tx, dbType)
		if err != nil {
			return nil, err
		}
	}

	var federationRelationships []FederatedTrustDomain
	if err := query.Find(&federationRelationships).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	if p != nil {
		p.Token = ""
		// Set token to the last ID of a non-empty page
		if len(federationRelationships) > 0 {
			lastEntry := federationRelationships[len(federationRelationships)-1]
			p.Token = fmt.Sprint(lastEntry.ID)
		}
	}

	resp := &datastore.ListFederationRelationshipsResponse{
		Pagination:              p,
		FederationRelationships: []*datastore.FederationRelationship{},
	}
	for _, model := range federationRelationships {
		federationRelationship, err := modelToFederationRelationship(tx, &model)
		if err != nil {
			return nil, err
		}

		resp.FederationRelationships = append(resp.FederationRelationships, federationRelationship)
	}

	return resp, nil
}

func updateFederationRelationship(tx *gorm.DB, fr *datastore.FederationRelationship, mask *types.FederationRelationshipMask) (*datastore.FederationRelationship, error) {
	var model FederatedTrustDomain
	err := tx.Where("trust_domain = ?", fr.TrustDomain.Name()).Take(&model).Error
	if err != nil {
		return nil, fmt.Errorf("unable to fetch federation relationship: %w", err)
	}

	if mask.BundleEndpointUrl {
		model.BundleEndpointURL = fr.BundleEndpointURL.String()
	}

	if mask.BundleEndpointProfile {
		model.BundleEndpointProfile = string(fr.BundleEndpointProfile)

		if fr.BundleEndpointProfile == datastore.BundleEndpointSPIFFE {
			model.EndpointSPIFFEID = fr.EndpointSPIFFEID.String()
		}
	}

	if mask.TrustDomainBundle && fr.TrustDomainBundle != nil {
		// overwrite current bundle
		_, err := setBundle(tx, fr.TrustDomainBundle)
		if err != nil {
			return nil, fmt.Errorf("unable to set bundle: %w", err)
		}
	}

	// Select writes the columns even when empty; Updates would skip zero values.
	if err := tx.Model(&model).Select("BundleEndpointURL", "BundleEndpointProfile", "EndpointSPIFFEID").Updates(&model).Error; err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	return modelToFederationRelationship(tx, &model)
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

func modelToFederationRelationship(tx *gorm.DB, model *FederatedTrustDomain) (*datastore.FederationRelationship, error) {
	bundleEndpointURL, err := url.Parse(model.BundleEndpointURL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse URL: %w", err)
	}

	td, err := spiffeid.TrustDomainFromString(model.TrustDomain)
	if err != nil {
		return nil, sqlcommon.NewWrappedSQLError(err)
	}

	fr := &datastore.FederationRelationship{
		TrustDomain:           td,
		BundleEndpointURL:     bundleEndpointURL,
		BundleEndpointProfile: datastore.BundleEndpointType(model.BundleEndpointProfile),
	}

	switch fr.BundleEndpointProfile {
	case datastore.BundleEndpointWeb:
	case datastore.BundleEndpointSPIFFE:
		endpointSPIFFEID, err := spiffeid.FromString(model.EndpointSPIFFEID)
		if err != nil {
			return nil, fmt.Errorf("unable to parse bundle endpoint SPIFFE ID: %w", err)
		}
		fr.EndpointSPIFFEID = endpointSPIFFEID
	default:
		return nil, fmt.Errorf("unknown bundle endpoint profile type: %q", model.BundleEndpointProfile)
	}

	trustDomainBundle, err := fetchBundle(tx, td.IDString())
	if err != nil {
		return nil, fmt.Errorf("unable to fetch bundle: %w", err)
	}
	fr.TrustDomainBundle = trustDomainBundle

	return fr, nil
}
