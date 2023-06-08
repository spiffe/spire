package trustdomain

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/protoutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/datastore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

// BundleRefresher is used by the service to refresh bundles.
type BundleRefresher interface {
	// TriggerConfigReload triggers the refresher to reload it's configuration
	TriggerConfigReload()

	// RefreshBundleFor refreshes the bundle for the given trust domain.
	RefreshBundleFor(ctx context.Context, td spiffeid.TrustDomain) (bool, error)
}

// Config is the service configuration.
type Config struct {
	DataStore       datastore.DataStore
	TrustDomain     spiffeid.TrustDomain
	BundleRefresher BundleRefresher
}

// Service implements the v1 trustdomain service.
type Service struct {
	trustdomainv1.UnsafeTrustDomainServer

	ds datastore.DataStore
	td spiffeid.TrustDomain
	br BundleRefresher
}

// New creates a new trustdomain service.
func New(config Config) *Service {
	return &Service{
		ds: config.DataStore,
		td: config.TrustDomain,
		br: config.BundleRefresher,
	}
}

// RegisterService registers the trustdomain service on the gRPC server.
func RegisterService(s *grpc.Server, service *Service) {
	trustdomainv1.RegisterTrustDomainServer(s, service)
}

func (s *Service) ListFederationRelationships(ctx context.Context, req *trustdomainv1.ListFederationRelationshipsRequest) (*trustdomainv1.ListFederationRelationshipsResponse, error) {
	log := rpccontext.Logger(ctx)

	listReq := &datastore.ListFederationRelationshipsRequest{}
	if req.PageSize > 0 {
		listReq.Pagination = &datastore.Pagination{
			PageSize: req.PageSize,
			Token:    req.PageToken,
		}
	}

	dsResp, err := s.ds.ListFederationRelationships(ctx, listReq)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to list federation relationships", err)
	}

	resp := &trustdomainv1.ListFederationRelationshipsResponse{}
	if dsResp.Pagination != nil {
		resp.NextPageToken = dsResp.Pagination.Token
	}

	for _, fr := range dsResp.FederationRelationships {
		tFederationRelationship, err := api.FederationRelationshipToProto(fr, req.OutputMask)
		if err != nil {
			return nil, api.MakeErr(log, codes.InvalidArgument, "failed to convert datastore response", err)
		}
		resp.FederationRelationships = append(resp.FederationRelationships, tFederationRelationship)
	}

	rpccontext.AuditRPC(ctx)
	return resp, nil
}

func (s *Service) GetFederationRelationship(ctx context.Context, req *trustdomainv1.GetFederationRelationshipRequest) (*types.FederationRelationship, error) {
	rpccontext.AddRPCAuditFields(ctx, logrus.Fields{telemetry.TrustDomainID: req.TrustDomain})

	log := rpccontext.Logger(ctx)

	trustDomain, err := spiffeid.TrustDomainFromString(req.TrustDomain)
	if err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "failed to parse trust domain", err)
	}

	dsResp, err := s.ds.FetchFederationRelationship(ctx, trustDomain)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to fetch federation relationship", err)
	}

	// if the entry is not found, FetchFederationRelationship returns nil, nil
	if dsResp == nil {
		return nil, api.MakeErr(log, codes.NotFound, "federation relationship does not exist", err)
	}

	tFederationRelationship, err := api.FederationRelationshipToProto(dsResp, req.OutputMask)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to convert datastore response", err)
	}

	rpccontext.AuditRPC(ctx)
	return tFederationRelationship, nil
}

func (s *Service) BatchCreateFederationRelationship(ctx context.Context, req *trustdomainv1.BatchCreateFederationRelationshipRequest) (*trustdomainv1.BatchCreateFederationRelationshipResponse, error) {
	var results []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result
	var triggerReload bool
	for _, eachRelationship := range req.FederationRelationships {
		r := s.createFederationRelationship(ctx, eachRelationship, req.OutputMask)
		if r.Status.Code == 0 {
			triggerReload = true
		}
		results = append(results, r)
		rpccontext.AuditRPCWithTypesStatus(ctx, r.Status, func() logrus.Fields {
			return fieldsFromRelationshipProto(eachRelationship, nil)
		})
	}

	if triggerReload {
		s.br.TriggerConfigReload()
	}

	return &trustdomainv1.BatchCreateFederationRelationshipResponse{
		Results: results,
	}, nil
}

func (s *Service) BatchUpdateFederationRelationship(ctx context.Context, req *trustdomainv1.BatchUpdateFederationRelationshipRequest) (*trustdomainv1.BatchUpdateFederationRelationshipResponse, error) {
	var results []*trustdomainv1.BatchUpdateFederationRelationshipResponse_Result
	var triggerReload bool
	for _, eachFR := range req.FederationRelationships {
		r := s.updateFederationRelationship(ctx, eachFR, req.InputMask, req.OutputMask)
		results = append(results, r)
		if r.Status.Code == 0 {
			triggerReload = true
		}
		rpccontext.AuditRPCWithTypesStatus(ctx, r.Status, func() logrus.Fields {
			return fieldsFromRelationshipProto(eachFR, req.InputMask)
		})
	}

	if triggerReload {
		s.br.TriggerConfigReload()
	}

	return &trustdomainv1.BatchUpdateFederationRelationshipResponse{
		Results: results,
	}, nil
}

func (s *Service) BatchDeleteFederationRelationship(ctx context.Context, req *trustdomainv1.BatchDeleteFederationRelationshipRequest) (*trustdomainv1.BatchDeleteFederationRelationshipResponse, error) {
	var results []*trustdomainv1.BatchDeleteFederationRelationshipResponse_Result
	var triggerReload bool
	for _, td := range req.TrustDomains {
		r := s.deleteFederationRelationship(ctx, td)
		if r.Status.Code == 0 {
			triggerReload = true
		}
		results = append(results, r)
		rpccontext.AuditRPCWithTypesStatus(ctx, r.Status, func() logrus.Fields {
			return logrus.Fields{telemetry.TrustDomainID: td}
		})
	}

	if triggerReload {
		s.br.TriggerConfigReload()
	}

	return &trustdomainv1.BatchDeleteFederationRelationshipResponse{
		Results: results,
	}, nil
}

func (s *Service) RefreshBundle(ctx context.Context, req *trustdomainv1.RefreshBundleRequest) (*emptypb.Empty, error) {
	log := rpccontext.Logger(ctx)

	trustDomain, err := spiffeid.TrustDomainFromString(req.GetTrustDomain())
	if err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "failed to parse trust domain", err)
	}

	log = log.WithField(telemetry.TrustDomainID, trustDomain.Name())
	rpccontext.AddRPCAuditFields(ctx, logrus.Fields{telemetry.TrustDomainID: req.TrustDomain})

	isManagedByBm, err := s.br.RefreshBundleFor(ctx, trustDomain)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to refresh bundle", err)
	}
	if !isManagedByBm {
		return nil, api.MakeErr(log, codes.NotFound, fmt.Sprintf("no relationship with trust domain %q", trustDomain), nil)
	}

	log.Debug("Bundle refreshed")
	rpccontext.AuditRPC(ctx)
	return &emptypb.Empty{}, nil
}

func (s *Service) createFederationRelationship(ctx context.Context, f *types.FederationRelationship, outputMask *types.FederationRelationshipMask) *trustdomainv1.BatchCreateFederationRelationshipResponse_Result {
	log := rpccontext.Logger(ctx)
	log = log.WithField(telemetry.TrustDomainID, f.TrustDomain)

	dsFederationRelationship, err := api.ProtoToFederationRelationship(f)
	if err != nil {
		return &trustdomainv1.BatchCreateFederationRelationshipResponse_Result{
			Status: api.MakeStatus(log, codes.InvalidArgument, "failed to convert federation relationship", err),
		}
	}

	if s.td.Compare(dsFederationRelationship.TrustDomain) == 0 {
		return &trustdomainv1.BatchCreateFederationRelationshipResponse_Result{
			Status: api.MakeStatus(log, codes.InvalidArgument, "unable to create federation relationship for server trust domain", nil),
		}
	}

	resp, err := s.ds.CreateFederationRelationship(ctx, dsFederationRelationship)
	if err != nil {
		return &trustdomainv1.BatchCreateFederationRelationshipResponse_Result{
			Status: api.MakeStatus(log, codes.Internal, "failed to create federation relationship", err),
		}
	}

	tFederationRelationship, err := api.FederationRelationshipToProto(resp, outputMask)
	if err != nil {
		return &trustdomainv1.BatchCreateFederationRelationshipResponse_Result{
			Status: api.MakeStatus(log, codes.Internal, "failed to convert datastore response", err),
		}
	}

	// Warning in case of SPIFFE endpoint that does not have a bundle
	if resp.TrustDomainBundle == nil && resp.BundleEndpointProfile == datastore.BundleEndpointSPIFFE {
		validateEndpointBundle(ctx, s.ds, log, resp.EndpointSPIFFEID)
	}

	log.Debug("Federation relationship created")

	return &trustdomainv1.BatchCreateFederationRelationshipResponse_Result{
		Status:                 api.OK(),
		FederationRelationship: tFederationRelationship,
	}
}

func (s *Service) updateFederationRelationship(ctx context.Context, fr *types.FederationRelationship, inputMask *types.FederationRelationshipMask, outputMask *types.FederationRelationshipMask) *trustdomainv1.BatchUpdateFederationRelationshipResponse_Result {
	log := rpccontext.Logger(ctx)
	log = log.WithField(telemetry.TrustDomainID, fr.TrustDomain)

	dFederationRelationship, err := api.ProtoToFederationRelationship(fr)
	if err != nil {
		return &trustdomainv1.BatchUpdateFederationRelationshipResponse_Result{
			Status: api.MakeStatus(log, codes.InvalidArgument, "failed to convert federation relationship", err),
		}
	}

	if inputMask == nil {
		inputMask = protoutil.AllTrueFederationRelationshipMask
	}

	resp, err := s.ds.UpdateFederationRelationship(ctx, dFederationRelationship, inputMask)
	if err != nil {
		return &trustdomainv1.BatchUpdateFederationRelationshipResponse_Result{
			Status: api.MakeStatus(log, codes.Internal, "failed to update federation relationship", err),
		}
	}

	tFederationRelationship, err := api.FederationRelationshipToProto(resp, outputMask)
	if err != nil {
		return &trustdomainv1.BatchUpdateFederationRelationshipResponse_Result{
			Status: api.MakeStatus(log, codes.Internal, "failed to convert federation relationship to proto", err),
		}
	}
	// Warning in case of SPIFFE endpoint that does not have a bundle
	if resp.TrustDomainBundle == nil && resp.BundleEndpointProfile == datastore.BundleEndpointSPIFFE {
		validateEndpointBundle(ctx, s.ds, log, resp.EndpointSPIFFEID)
	}
	log.Debug("Federation relationship updated")

	return &trustdomainv1.BatchUpdateFederationRelationshipResponse_Result{
		Status:                 api.OK(),
		FederationRelationship: tFederationRelationship,
	}
}

func (s *Service) deleteFederationRelationship(ctx context.Context, td string) *trustdomainv1.BatchDeleteFederationRelationshipResponse_Result {
	log := rpccontext.Logger(ctx)

	if td == "" {
		return &trustdomainv1.BatchDeleteFederationRelationshipResponse_Result{
			TrustDomain: td,
			Status:      api.MakeStatus(log, codes.InvalidArgument, "missing trust domain", nil),
		}
	}

	log = log.WithField(telemetry.TrustDomainID, td)

	trustDomain, err := spiffeid.TrustDomainFromString(td)
	if err != nil {
		return &trustdomainv1.BatchDeleteFederationRelationshipResponse_Result{
			TrustDomain: td,
			Status:      api.MakeStatus(log, codes.InvalidArgument, "failed to parse trust domain", err),
		}
	}

	err = s.ds.DeleteFederationRelationship(ctx, trustDomain)
	switch status.Code(err) {
	case codes.OK:
		log.Debug("Federation relationship deleted")
		return &trustdomainv1.BatchDeleteFederationRelationshipResponse_Result{
			TrustDomain: trustDomain.Name(),
			Status:      api.OK(),
		}
	case codes.NotFound:
		return &trustdomainv1.BatchDeleteFederationRelationshipResponse_Result{
			TrustDomain: trustDomain.Name(),
			Status:      api.MakeStatus(log, codes.NotFound, "federation relationship not found", nil),
		}
	default:
		return &trustdomainv1.BatchDeleteFederationRelationshipResponse_Result{
			TrustDomain: trustDomain.Name(),
			Status:      api.MakeStatus(log, codes.Internal, "failed to delete federation relationship", err),
		}
	}
}

func fieldsFromRelationshipProto(proto *types.FederationRelationship, mask *types.FederationRelationshipMask) logrus.Fields {
	fields := logrus.Fields{}

	if mask == nil {
		mask = protoutil.AllTrueFederationRelationshipMask
	}

	if proto == nil {
		return fields
	}

	if proto.TrustDomain != "" {
		fields[telemetry.TrustDomainID] = proto.TrustDomain
	}

	if mask.BundleEndpointUrl {
		fields[telemetry.BundleEndpointURL] = proto.BundleEndpointUrl
	}

	if mask.BundleEndpointProfile {
		switch profile := proto.BundleEndpointProfile.(type) {
		case *types.FederationRelationship_HttpsWeb:
			fields[telemetry.BundleEndpointProfile] = datastore.BundleEndpointWeb
		case *types.FederationRelationship_HttpsSpiffe:
			fields[telemetry.BundleEndpointProfile] = datastore.BundleEndpointSPIFFE
			fields[telemetry.EndpointSpiffeID] = profile.HttpsSpiffe.EndpointSpiffeId
		}
	}

	if mask.TrustDomainBundle {
		if proto.TrustDomainBundle != nil {
			bundleFields := api.FieldsFromBundleProto(proto.TrustDomainBundle, nil)
			for key, value := range bundleFields {
				fields["bundle_"+key] = value
			}
		}
	}

	return fields
}

func validateEndpointBundle(ctx context.Context, ds datastore.DataStore, log logrus.FieldLogger, endpointSPIFFEID spiffeid.ID) {
	bundle, err := ds.FetchBundle(ctx, endpointSPIFFEID.TrustDomain().IDString())
	if err != nil {
		log.WithField(telemetry.EndpointSpiffeID, endpointSPIFFEID).Warn("failed to check whether a bundle exists for the endpoint SPIFFE ID trust domain")

		return
	}
	// Bundle is nil when not found
	if bundle == nil {
		log.WithField(telemetry.EndpointSpiffeID, endpointSPIFFEID.String()).Warn("bundle not found for the endpoint SPIFFE ID trust domain")
	}
}
