package bundle

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire-next/api/server/bundle/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RegisterService registers the bundle service on the gRPC server.
func RegisterService(s *grpc.Server, service *Service) {
	bundle.RegisterBundleServer(s, service)
}

type UpstreamPublisher interface {
	PublishJWTKey(ctx context.Context, jwtKey *common.PublicKey) ([]*common.PublicKey, error)
}

type UpstreamPublisherFunc func(ctx context.Context, jwtKey *common.PublicKey) ([]*common.PublicKey, error)

func (fn UpstreamPublisherFunc) PublishJWTKey(ctx context.Context, jwtKey *common.PublicKey) ([]*common.PublicKey, error) {
	return fn(ctx, jwtKey)
}

// Config is the service configuration
type Config struct {
	Datastore         datastore.DataStore
	TrustDomain       spiffeid.TrustDomain
	UpstreamPublisher UpstreamPublisher
}

// New creates a new bundle service
func New(config Config) *Service {
	return &Service{
		ds: config.Datastore,
		td: config.TrustDomain,
		up: config.UpstreamPublisher,
	}
}

// Service implements the v1 bundle service
type Service struct {
	ds datastore.DataStore
	td spiffeid.TrustDomain
	up UpstreamPublisher
}

func (s *Service) GetBundle(ctx context.Context, req *bundle.GetBundleRequest) (*types.Bundle, error) {
	log := rpccontext.Logger(ctx)

	dsResp, err := s.ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: s.td.IDString(),
	})
	if err != nil {
		log.Errorf("Failed to fetch bundle: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to fetch bundle: %v", err)
	}

	if dsResp.Bundle == nil {
		log.Error("Bundle not found")
		return nil, status.Error(codes.NotFound, "bundle not found")
	}

	bundle, err := api.BundleToProto(dsResp.Bundle)
	if err != nil {
		log.WithError(err).Error("Failed to convert bundle")
		return nil, status.Errorf(codes.Internal, "failed to convert bundle: %v", err)
	}

	applyBundleMask(bundle, req.OutputMask)
	return bundle, nil
}

func (s *Service) AppendBundle(ctx context.Context, req *bundle.AppendBundleRequest) (*types.Bundle, error) {
	log := rpccontext.Logger(ctx)

	if req.Bundle == nil {
		log.Error("Invalid request: missing bundle")
		return nil, status.Error(codes.InvalidArgument, "missing bundle")
	}

	td, err := spiffeid.TrustDomainFromString(req.Bundle.TrustDomain)
	if err != nil {
		log.WithError(err).Errorf("Invalid request: trust domain argument is not a valid SPIFFE ID: %q", req.Bundle.TrustDomain)
		return nil, status.Errorf(codes.InvalidArgument, "trust domain argument is not a valid SPIFFE ID: %q", req.Bundle.TrustDomain)
	}

	if s.td.Compare(td) != 0 {
		log.Error("Invalid request: only the trust domain of the server can be appended")
		return nil, status.Error(codes.InvalidArgument, "only the trust domain of the server can be appended")
	}

	dsResp, err := s.ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: s.td.String(),
	})
	if err != nil {
		log.WithError(err).Error("Failed to fetch server bundle")
		return nil, status.Errorf(codes.Internal, "failed to fetch server bundle: %v", err)
	}

	if dsResp.Bundle == nil {
		log.Error("Failed to fetch server bundle: not found")
		return nil, status.Errorf(codes.NotFound, "failed to fetch server bundle: not found")
	}

	applyBundleMask(req.Bundle, req.InputMask)

	dsBundle, err := api.ProtoToBundle(req.Bundle)
	if err != nil {
		log.WithError(err).Error("Failed to convert bundle")
		return nil, status.Errorf(codes.Internal, "failed to convert bundle: %v", err)
	}

	resp, err := s.ds.AppendBundle(ctx, &datastore.AppendBundleRequest{
		Bundle: &common.Bundle{
			TrustDomainId:  td.String(),
			JwtSigningKeys: dsBundle.JwtSigningKeys,
			RootCas:        dsBundle.RootCas,
		},
	})
	if err != nil {
		log.WithError(err).Error("Failed to append bundle")
		return nil, status.Errorf(codes.Internal, "failed to append bundle: %v", err)
	}

	bundle, err := api.BundleToProto(resp.Bundle)
	if err != nil {
		log.WithError(err).Error("Failed to convert bundle")
		return nil, status.Errorf(codes.Internal, "failed to convert bundle: %v", err)
	}

	applyBundleMask(bundle, req.OutputMask)
	return bundle, nil
}

func (s *Service) PublishJWTAuthority(ctx context.Context, req *bundle.PublishJWTAuthorityRequest) (*bundle.PublishJWTAuthorityResponse, error) {
	log := rpccontext.Logger(ctx)

	if err := rpccontext.RateLimit(ctx, 1); err != nil {
		log.WithError(err).Error("Rejecting request due to key publishing rate limiting")
		return nil, err
	}

	if req.JwtAuthority == nil {
		log.Error("Invalid request: missing JWT authority")
		return nil, status.Error(codes.InvalidArgument, "missing JWT authority")
	}

	keys, err := api.ParseJWTAuthorities([]*types.JWTKey{req.JwtAuthority})
	if err != nil {
		log.WithError(err).Error("Invalid request: invalid JWT authority")
		return nil, status.Errorf(codes.InvalidArgument, "invalid JWT authority: %v", err)
	}

	resp, err := s.up.PublishJWTKey(ctx, keys[0])
	if err != nil {
		log.WithError(err).Error("Failed to publish JWT key")
		return nil, status.Errorf(codes.Internal, "failed to publish JWT key: %v", err)
	}

	// TODO: after pushing authoriry, may we reset dsCache? (Track on #1631)
	// dsCache.DeleteBundleEntry(s.td.String())

	return &bundle.PublishJWTAuthorityResponse{
		JwtAuthorities: api.PublicKeysToProto(resp),
	}, nil
}

func (s *Service) ListFederatedBundles(ctx context.Context, req *bundle.ListFederatedBundlesRequest) (*bundle.ListFederatedBundlesResponse, error) {
	log := rpccontext.Logger(ctx)

	listReq := &datastore.ListBundlesRequest{}

	// Set pagination parameters
	if req.PageSize > 0 {
		listReq.Pagination = &datastore.Pagination{
			PageSize: req.PageSize,
			Token:    req.PageToken,
		}
	}

	dsResp, err := s.ds.ListBundles(ctx, listReq)
	if err != nil {
		log.WithError(err).Error("Failed to list bundles")
		return nil, status.Errorf(codes.Internal, "failed to list bundles: %v", err)
	}

	resp := &bundle.ListFederatedBundlesResponse{}

	if dsResp.Pagination != nil {
		resp.NextPageToken = dsResp.Pagination.Token
	}

	for _, dsBundle := range dsResp.Bundles {
		td, err := spiffeid.TrustDomainFromString(dsBundle.TrustDomainId)
		if err != nil {
			log.WithFields(logrus.Fields{
				logrus.ErrorKey:         err,
				telemetry.TrustDomainID: dsBundle.TrustDomainId,
			}).Error("Bundle has an invalid trust domain ID")
			return nil, status.Errorf(codes.Internal, "bundle has an invalid trust domain ID: %q", dsBundle.TrustDomainId)
		}

		// Filter server bundle
		if s.td.Compare(td) == 0 {
			continue
		}

		b, err := api.BundleToProto(dsBundle)
		if err != nil {
			log.WithError(err).Error("Failed to convert bundle")
			return nil, status.Errorf(codes.Internal, "failed to convert bundle: %v", err)
		}
		applyBundleMask(b, req.OutputMask)
		resp.Bundles = append(resp.Bundles, b)
	}

	return resp, nil
}

func (s *Service) GetFederatedBundle(ctx context.Context, req *bundle.GetFederatedBundleRequest) (*types.Bundle, error) {
	log := rpccontext.Logger(ctx)

	td, err := spiffeid.TrustDomainFromString(req.TrustDomain)
	if err != nil {
		log.Errorf("Trust domain argument is not a valid SPIFFE ID: %q", req.TrustDomain)
		return nil, status.Errorf(codes.InvalidArgument, "trust domain argument is not a valid SPIFFE ID: %q", req.TrustDomain)
	}

	if s.td.Compare(td) == 0 {
		log.Errorf("%q is this server own trust domain, use GetBundle RPC instead", td.String())
		return nil, status.Errorf(codes.InvalidArgument, "%q is this server own trust domain, use GetBundle RPC instead", td.String())
	}

	dsResp, err := s.ds.FetchBundle(ctx, &datastore.FetchBundleRequest{
		TrustDomainId: td.IDString(),
	})
	if err != nil {
		log.Errorf("Failed to fetch bundle: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to fetch bundle: %v", err)
	}

	if dsResp.Bundle == nil {
		log.Errorf("Bundle for %q not found", req.TrustDomain)
		return nil, status.Errorf(codes.NotFound, "bundle for %q not found", req.TrustDomain)
	}

	b, err := api.BundleToProto(dsResp.Bundle)
	if err != nil {
		log.WithError(err).Error("Failed to convert bundle")
		return nil, status.Errorf(codes.Internal, "failed to convert bundle: %v", err)
	}

	applyBundleMask(b, req.OutputMask)

	return b, nil
}

func (s *Service) BatchCreateFederatedBundle(ctx context.Context, req *bundle.BatchCreateFederatedBundleRequest) (*bundle.BatchCreateFederatedBundleResponse, error) {
	var results []*bundle.BatchCreateFederatedBundleResponse_Result
	for _, b := range req.Bundle {
		results = append(results, s.createFederatedBundle(ctx, b, req.OutputMask))
	}

	return &bundle.BatchCreateFederatedBundleResponse{
		Results: results,
	}, nil
}

func (s *Service) createFederatedBundle(ctx context.Context, b *types.Bundle, outputMask *types.BundleMask) *bundle.BatchCreateFederatedBundleResponse_Result {
	log := rpccontext.Logger(ctx).WithField(telemetry.TrustDomainID, b.TrustDomain)

	td, err := spiffeid.TrustDomainFromString(b.TrustDomain)
	if err != nil {
		log.WithError(err).Error("Invalid request: trust domain argument is not valid")
		return &bundle.BatchCreateFederatedBundleResponse_Result{
			Status: api.CreateStatus(codes.InvalidArgument, "trust domain argument is not valid: %q", b.TrustDomain),
		}
	}

	if s.td.Compare(td) == 0 {
		log.Error("Invalid request: creating a federated bundle for the server's own trust domain is not allowed")
		return &bundle.BatchCreateFederatedBundleResponse_Result{
			Status: api.CreateStatus(codes.InvalidArgument, "creating a federated bundle for the server's own trust domain (%s) s not allowed", td.String()),
		}
	}

	dsBundle, err := api.ProtoToBundle(b)
	if err != nil {
		log.WithError(err).Error("Failed to convert bundle")
		return &bundle.BatchCreateFederatedBundleResponse_Result{
			Status: api.CreateStatus(codes.Internal, "failed to convert bundle: %v", err),
		}
	}
	resp, err := s.ds.CreateBundle(ctx, &datastore.CreateBundleRequest{
		Bundle: dsBundle,
	})

	switch status.Code(err) {
	case codes.OK:
	case codes.AlreadyExists:
		log.WithError(err).Error("Bundle already exists")
		return &bundle.BatchCreateFederatedBundleResponse_Result{
			Status: api.CreateStatus(codes.AlreadyExists, "bundle already exists"),
		}
	default:
		log.WithError(err).Error("Unable to create bundle")
		return &bundle.BatchCreateFederatedBundleResponse_Result{
			Status: api.CreateStatus(codes.Internal, "unable to create bundle: %v", err),
		}
	}

	protoBundle, err := api.BundleToProto(resp.Bundle)
	if err != nil {
		log.WithError(err).Error("Failed to convert bundle")
		return &bundle.BatchCreateFederatedBundleResponse_Result{
			Status: api.CreateStatus(codes.Internal, "failed to convert bundle: %v", err),
		}
	}

	applyBundleMask(protoBundle, outputMask)

	log.Info("Bundle created successfully")
	return &bundle.BatchCreateFederatedBundleResponse_Result{
		Status: api.CreateStatus(codes.OK, "bundle created successfully for trust domain: %q", td.String()),
		Bundle: protoBundle,
	}
}

func (s *Service) setFederatedBundle(ctx context.Context, b *types.Bundle, outputMask *types.BundleMask) *bundle.BatchSetFederatedBundleResponse_Result {
	log := rpccontext.Logger(ctx).WithField(telemetry.TrustDomainID, b.TrustDomain)

	td, err := spiffeid.TrustDomainFromString(b.TrustDomain)
	if err != nil {
		log.WithError(err).Error("Invalid request: trust domain argument is not valid")
		return &bundle.BatchSetFederatedBundleResponse_Result{
			Status: api.CreateStatus(codes.InvalidArgument, "trust domain argument is not valid: %q", b.TrustDomain),
		}
	}

	if s.td.Compare(td) == 0 {
		log.Error("Invalid request: setting a federated bundle for the server's own trust domain is not allowed")
		return &bundle.BatchSetFederatedBundleResponse_Result{
			Status: api.CreateStatus(codes.InvalidArgument, "setting a federated bundle for the server's own trust domain (%s) s not allowed", td.String()),
		}
	}

	dsBundle, err := api.ProtoToBundle(b)
	if err != nil {
		log.WithError(err).Error("Failed to convert bundle")
		return &bundle.BatchSetFederatedBundleResponse_Result{
			Status: api.CreateStatus(codes.Internal, "failed to convert bundle: %v", err),
		}
	}
	resp, err := s.ds.SetBundle(ctx, &datastore.SetBundleRequest{
		Bundle: dsBundle,
	})

	if err != nil {
		log.WithError(err).Error("Unable to set bundle")
		return &bundle.BatchSetFederatedBundleResponse_Result{
			Status: api.CreateStatus(codes.Internal, "unable to set bundle: %v", err),
		}
	}

	protoBundle, err := api.BundleToProto(resp.Bundle)
	if err != nil {
		log.WithError(err).Error("Failed to convert bundle")
		return &bundle.BatchSetFederatedBundleResponse_Result{
			Status: api.CreateStatus(codes.Internal, "failed to convert bundle: %v", err),
		}
	}

	applyBundleMask(protoBundle, outputMask)

	log.Info("Bundle set successfully")
	return &bundle.BatchSetFederatedBundleResponse_Result{
		Status: api.CreateStatus(codes.OK, "bundle set successfully for trust domain: %q", td.String()),
		Bundle: protoBundle,
	}
}

func (s *Service) BatchUpdateFederatedBundle(ctx context.Context, req *bundle.BatchUpdateFederatedBundleRequest) (*bundle.BatchUpdateFederatedBundleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method BatchUpdateFederatedBundle not implemented")
}

func (s *Service) BatchSetFederatedBundle(ctx context.Context, req *bundle.BatchSetFederatedBundleRequest) (*bundle.BatchSetFederatedBundleResponse, error) {
	var results []*bundle.BatchSetFederatedBundleResponse_Result
	for _, b := range req.Bundle {
		results = append(results, s.setFederatedBundle(ctx, b, req.OutputMask))
	}

	return &bundle.BatchSetFederatedBundleResponse{
		Results: results,
	}, nil
}

func (s *Service) BatchDeleteFederatedBundle(ctx context.Context, req *bundle.BatchDeleteFederatedBundleRequest) (*bundle.BatchDeleteFederatedBundleResponse, error) {
	var results []*bundle.BatchDeleteFederatedBundleResponse_Result
	for _, trustDomain := range req.TrustDomains {
		results = append(results, s.deleteFederatedBundle(ctx, trustDomain))
	}

	return &bundle.BatchDeleteFederatedBundleResponse{
		Results: results,
	}, nil
}

func (s *Service) deleteFederatedBundle(ctx context.Context, trustDomain string) *bundle.BatchDeleteFederatedBundleResponse_Result {
	log := rpccontext.Logger(ctx).WithField(telemetry.TrustDomainID, trustDomain)

	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		log.WithError(err).Error("Invalid request: malformed trust domain")
		return &bundle.BatchDeleteFederatedBundleResponse_Result{
			Status:      api.CreateStatus(codes.InvalidArgument, "malformed trust domain: %v", err),
			TrustDomain: trustDomain,
		}
	}

	if s.td.Compare(td) == 0 {
		log.Error("Invalid request: removing the bundle for the server trust domain is not allowed")
		return &bundle.BatchDeleteFederatedBundleResponse_Result{
			TrustDomain: trustDomain,
			Status:      api.CreateStatus(codes.InvalidArgument, "removing the bundle for the server trust domain is not allowed"),
		}
	}

	_, err = s.ds.DeleteBundle(ctx, &datastore.DeleteBundleRequest{
		TrustDomainId: td.String(),
		// TODO: what mode must we use here?
		Mode: datastore.DeleteBundleRequest_RESTRICT,
	})
	switch status.Code(err) {
	case codes.OK:
		return &bundle.BatchDeleteFederatedBundleResponse_Result{
			Status:      api.OK(),
			TrustDomain: trustDomain,
		}
	case codes.NotFound:
		return &bundle.BatchDeleteFederatedBundleResponse_Result{
			Status:      api.StatusFromError(err),
			TrustDomain: trustDomain,
		}
	default:
		log.WithError(err).Error("Failed to delete federated bundle")
		return &bundle.BatchDeleteFederatedBundleResponse_Result{
			TrustDomain: trustDomain,
			Status:      api.CreateStatus(codes.Internal, "failed to delete federated bundle: %v", err),
		}
	}
}

func applyBundleMask(b *types.Bundle, mask *types.BundleMask) {
	if mask == nil {
		return
	}

	if !mask.RefreshHint {
		b.RefreshHint = 0
	}

	if !mask.SequenceNumber {
		b.SequenceNumber = 0
	}

	if !mask.X509Authorities {
		b.X509Authorities = nil
	}

	if !mask.JwtAuthorities {
		b.JwtAuthorities = nil
	}
}
