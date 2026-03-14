package cassandra

import (
	"context"
	"errors"
	"fmt"
	"strings"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
	datastorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/datastore/v1alpha1"
	"github.com/tjons/cassandra-toolbox/qb/pages"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var AllTrueFederationRelationshipMask = &datastorev1.FederationRelationshipMask{
	BundleEndpointUrl:     true,
	BundleEndpointProfile: true,
	TrustDomainBundle:     true,
}

func (p *Plugin) federationRelationshipExists(ctx context.Context, trustDomainID string) (bool, error) {
	var id string
	err := p.db.session.Query(`SELECT trust_domain FROM federated_trust_domains WHERE trust_domain = ?`, trustDomainID).
		Consistency(p.db.cfg.ReadConsistency).ScanContext(ctx, &id)
	if err != nil {
		if errors.Is(err, gocql.ErrNotFound) {
			return false, nil
		}
		return false, newWrappedCassandraError(fmt.Errorf("unable to check if federation relationship exists: %w", err))
	}
	return true, nil
}

func (p *Plugin) CreateFederationRelationship(
	ctx context.Context,
	fr *datastorev1.CreateFederationRelationshipRequest,
) (*datastorev1.CreateFederationRelationshipResponse, error) {
	if err := validateFederationRelationship(fr.Relationship, AllTrueFederationRelationshipMask); err != nil {
		return nil, err
	}

	exists, err := p.federationRelationshipExists(ctx, fr.Relationship.TrustDomainId)
	if err != nil {
		return nil, newWrappedCassandraError(fmt.Errorf("unable to check if federation relationship exists: %w", err))
	}
	if exists {
		return nil, status.Error(codes.AlreadyExists, "federation relationship already exists")
	}

	createQ := `
		INSERT INTO federated_trust_domains (
			created_at,
			updated_at,
			trust_domain,
			bundle_endpoint_url,
			bundle_endpoint_profile,
			endpoint_spiffe_id
		) VALUES (toTimestamp(now()), toTimestamp(now()), ?, ?, ?, ?)
	`

	if fr.Relationship.TrustDomainBundle != nil {
		_, err := p.SetBundle(ctx, &datastorev1.SetBundleRequest{
			Bundle: fr.Relationship.TrustDomainBundle,
		})
		if err != nil {
			return nil, fmt.Errorf("unable to set bundle: %w", err)
		}
	}

	var esi string
	if fr.Relationship.BundleEndpointType == datastorev1.BundleEndpointType_BUNDLE_ENDPOINT_TYPE_SPIFFE {
		esi = fr.Relationship.GetBundleEndpointSpiffeId()
	}

	err = p.db.session.Query(createQ,
		fr.Relationship.TrustDomainId,
		fr.Relationship.BundleEndpointUrl,
		fr.Relationship.BundleEndpointType.String(),
		esi,
	).Consistency(p.db.cfg.WriteConsistency).Exec()
	if err != nil {
		return nil, newWrappedCassandraError(fmt.Errorf("unable to create federation relationship: %w", err))
	}

	return &datastorev1.CreateFederationRelationshipResponse{
		Relationship: fr.Relationship,
	}, nil
}

func (p *Plugin) FetchFederationRelationship(ctx context.Context, req *datastorev1.FetchFederationRelationshipRequest) (*datastorev1.FetchFederationRelationshipResponse, error) {
	if req.GetTrustDomainId() == "" {
		return nil, status.Error(codes.InvalidArgument, "trust domain is required")
	}

	record := new(datastorev1.FederationRelationship)
	fetchQ := `
		SELECT
			trust_domain,
			bundle_endpoint_url,
			bundle_endpoint_profile,
			endpoint_spiffe_id
		FROM federated_trust_domains
		WHERE trust_domain = ?
	`

	var bundleEndpointType string
	if err := p.db.session.Query(fetchQ, req.GetTrustDomainId()).Consistency(p.db.cfg.ReadConsistency).ScanContext(
		ctx,
		&record.TrustDomainId,
		&record.BundleEndpointUrl,
		&bundleEndpointType,
		&record.BundleEndpointSpiffeId,
	); err != nil {
		if errors.Is(err, gocql.ErrNotFound) {
			return nil, nil
		}
		return nil, newWrappedCassandraError(fmt.Errorf("unable to fetch federation relationship: %w", err))
	}

	trustDomainBundle, err := p.fetchBundle(ctx, req.GetTrustDomainId())
	if err != nil && !errors.Is(err, gocql.ErrNotFound) {
		return nil, fmt.Errorf("unable to fetch bundle: %w", err)
	}
	record.TrustDomainBundle = trustDomainBundle

	if bundleEndpointType != "" {
		record.BundleEndpointType = datastorev1.BundleEndpointType(datastorev1.BundleEndpointType_value[bundleEndpointType])
	}

	return &datastorev1.FetchFederationRelationshipResponse{
		Relationship: record,
	}, nil
}

func (p *Plugin) ListFederationRelationships(ctx context.Context, req *datastorev1.ListFederationRelationshipsRequest) (*datastorev1.ListFederationRelationshipsResponse, error) {
	pager := pages.NewQueryPaginator(req.GetPagination() != nil, req.GetPagination().GetPageSize(), req.GetPagination().GetPageToken())
	if err := pager.Validate(); err != nil {
		return nil, err
	}

	listQ := `SELECT
			trust_domain,
			bundle_endpoint_url,
			bundle_endpoint_profile,
			endpoint_spiffe_id
		FROM federated_trust_domains
		ALLOW FILTERING
	`
	query := p.db.session.Query(listQ).Consistency(p.db.cfg.ReadConsistency)
	pager.BindToQuery(query)

	resp := &datastorev1.ListFederationRelationshipsResponse{
		Relationships: []*datastorev1.FederationRelationship{},
	}
	iter := query.IterContext(ctx)
	pager.ForIter(iter)
	scanner := iter.Scanner()
	for scanner.Next() {
		record := new(datastorev1.FederationRelationship)
		var bundleEndpointType string
		if err := scanner.Scan(
			&record.TrustDomainId,
			&record.BundleEndpointUrl,
			&bundleEndpointType,
			&record.BundleEndpointSpiffeId,
		); err != nil {
			return nil, newWrappedCassandraError(fmt.Errorf("unable to scan federation relationship: %w", err))
		}

		trustDomainBundle, err := p.fetchBundle(ctx, record.GetTrustDomainId())
		if err != nil && !errors.Is(err, gocql.ErrNotFound) {
			return nil, fmt.Errorf("unable to fetch bundle: %w", err)
		}
		record.TrustDomainBundle = trustDomainBundle

		if bundleEndpointType != "" {
			record.BundleEndpointType = datastorev1.BundleEndpointType(datastorev1.BundleEndpointType_value[bundleEndpointType])
		}

		resp.Relationships = append(resp.Relationships, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, newWrappedCassandraError(fmt.Errorf("unable to list federation relationships: %w", err))
	}

	resp.Pagination = responsePaginationFromPager(pager)
	// nextPageState := iter.PageState()

	// if req.Pagination != nil {
	// 	resp.Pagination = &datastore.Pagination{
	// 		PageSize: req.Pagination.PageSize,
	// 	}

	// 	// TODO(tjons): at a minimum, toss this behind a feature flag
	// 	peeker := p.db.session.Query(listQ).PageSize(1).PageState(nextPageState).IterContext(ctx)
	// 	if peeker.NumRows() > 0 {
	// 		resp.Pagination.Token = base64.URLEncoding.Strict().EncodeToString(nextPageState)
	// 	}
	// 	if err := peeker.Close(); err != nil {
	// 		return nil, newWrappedCassandraError(fmt.Errorf("unable to determine pagination token: %w", err))
	// 	}
	// }

	return resp, nil
}

func (p *Plugin) DeleteFederationRelationship(ctx context.Context, req *datastorev1.DeleteFederationRelationshipRequest) (*datastorev1.DeleteFederationRelationshipResponse, error) {
	if req.GetTrustDomainId() == "" {
		return nil, status.Error(codes.InvalidArgument, "trust domain is required")
	}

	fr, err := p.FetchFederationRelationship(ctx, &datastorev1.FetchFederationRelationshipRequest{
		TrustDomainId: req.GetTrustDomainId(),
	})
	if err != nil {
		return nil, err
	}
	if fr == nil {
		return nil, status.Error(codes.NotFound, NotFoundErr.Error())
	}

	deleteQ := `DELETE FROM federated_trust_domains WHERE trust_domain = ?`
	err = p.db.session.Query(deleteQ, req.GetTrustDomainId()).Consistency(p.db.cfg.WriteConsistency).Exec()
	if err != nil {
		if errors.Is(err, gocql.ErrNotFound) {
			return nil, status.Error(codes.NotFound, NotFoundErr.Error())
		}
		return nil, newWrappedCassandraError(fmt.Errorf("unable to delete federation relationship: %w", err))
	}

	return &datastorev1.DeleteFederationRelationshipResponse{}, nil
}

func (p *Plugin) UpdateFederationRelationship(
	ctx context.Context,
	req *datastorev1.UpdateFederationRelationshipRequest,
) (*datastorev1.UpdateFederationRelationshipResponse, error) {
	if req == nil || req.GetRelationship() == nil {
		return nil, status.Error(codes.InvalidArgument, "federation relationship is required")
	}

	if err := validateFederationRelationship(req.GetRelationship(), req.GetMask()); err != nil {
		return nil, err
	}

	exists, err := p.federationRelationshipExists(ctx, req.GetRelationship().TrustDomainId)
	if err != nil {
		return nil, newWrappedCassandraError(fmt.Errorf("unable to check if federation relationship exists: %w", err))
	}
	if !exists {
		return nil, status.Error(codes.NotFound, fmt.Errorf("unable to fetch federation relationship: %w", NotFoundErr).Error())
	}

	args := []any{}
	fields := []string{}

	if req.GetMask().GetBundleEndpointUrl() {
		fields = append(fields, "bundle_endpoint_url = ?")
		args = append(args, req.GetRelationship().GetBundleEndpointUrl())
	}

	if req.GetMask().GetBundleEndpointProfile() {
		fields = append(fields, "bundle_endpoint_profile = ?")
		args = append(args, req.GetRelationship().GetBundleEndpointType().String())

		if req.GetRelationship().GetBundleEndpointType() == datastorev1.BundleEndpointType_BUNDLE_ENDPOINT_TYPE_SPIFFE {
			fields = append(fields, "endpoint_spiffe_id = ?")
			args = append(args, req.GetRelationship().GetBundleEndpointSpiffeId())
		}
	}

	if req.GetMask().GetTrustDomainBundle() && req.GetRelationship().GetTrustDomainBundle() != nil {
		_, err := p.SetBundle(ctx, &datastorev1.SetBundleRequest{
			Bundle: req.GetRelationship().GetTrustDomainBundle(), // TODO(tjons): handle this in a batch
		})

		if err != nil {
			return nil, fmt.Errorf("unable to set bundle: %w", err)
		}
	}

	updateQ := strings.Builder{}
	updateQ.WriteString("UPDATE federated_trust_domains SET updated_at = toTimestamp(now())")
	for _, field := range fields {
		updateQ.WriteString(", ")
		updateQ.WriteString(field)
	}
	updateQ.WriteString(" WHERE trust_domain = ?")
	args = append(args, req.GetRelationship().GetTrustDomainId())

	err = p.db.session.Query(updateQ.String(), args...).Consistency(p.db.cfg.WriteConsistency).Exec()
	if err != nil {
		return nil, newWrappedCassandraError(fmt.Errorf("unable to update federation relationship: %w", err))
	}

	fetchResp, err := p.FetchFederationRelationship(ctx, &datastorev1.FetchFederationRelationshipRequest{
		TrustDomainId: req.GetRelationship().GetTrustDomainId(),
	})
	if err != nil {
		return nil, err
	}
	return &datastorev1.UpdateFederationRelationshipResponse{
		Relationship: fetchResp.GetRelationship(),
	}, nil
}

func validateFederationRelationship(fr *datastorev1.FederationRelationship, mask *datastorev1.FederationRelationshipMask) error {
	if fr == nil {
		return status.Error(codes.InvalidArgument, "federation relationship is nil")
	}

	if len(fr.TrustDomainId) == 0 {
		return status.Error(codes.InvalidArgument, "trust domain is required")
	}

	if mask.BundleEndpointUrl && len(fr.BundleEndpointUrl) == 0 {
		return status.Error(codes.InvalidArgument, "bundle endpoint URL is required")
	}

	if mask.BundleEndpointProfile {
		switch fr.BundleEndpointType {
		case datastorev1.BundleEndpointType_BUNDLE_ENDPOINT_TYPE_WEB:
		case datastorev1.BundleEndpointType_BUNDLE_ENDPOINT_TYPE_SPIFFE:
			if len(fr.BundleEndpointSpiffeId) == 0 {
				return status.Error(codes.InvalidArgument, "bundle endpoint SPIFFE ID is required")
			}
		default:
			return status.Errorf(codes.Unknown, "unknown bundle endpoint profile type: %q", fr.BundleEndpointType)
		}
	}

	return nil
}
