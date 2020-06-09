package bundle

import (
	"context"
	"crypto/x509"
	"errors"

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

// Config is the service configuration
type Config struct {
	Datastore   datastore.DataStore
	TrustDomain spiffeid.TrustDomain
}

// New creates a new bundle service
func New(config Config) *Service {
	return &Service{
		ds: config.Datastore,
		td: config.TrustDomain,
	}
}

// Service implements the v1 bundle service
type Service struct {
	ds datastore.DataStore
	td spiffeid.TrustDomain
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

	rootCAs, err := parseX509Authorities(req.Bundle.X509Authorities)
	if err != nil {
		log.WithError(err).Error("Invalid request: invalid X509 authority")
		return nil, status.Errorf(codes.InvalidArgument, "invalid X509 authority: %v", err)
	}

	jwtKeys, err := parseJWTAuthorities(req.Bundle.JwtAuthorities)
	if err != nil {
		log.WithError(err).Error("Invalid request: invalid JWT authority")
		return nil, status.Errorf(codes.InvalidArgument, "invalid JWT authority: %v", err)
	}

	resp, err := s.ds.AppendBundle(ctx, &datastore.AppendBundleRequest{
		Bundle: &common.Bundle{
			TrustDomainId:  td.String(),
			JwtSigningKeys: jwtKeys,
			RootCas:        rootCAs,
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

func parseX509Authorities(certs []*types.X509Certificate) ([]*common.Certificate, error) {
	var rootCAs []*common.Certificate
	for _, rootCA := range certs {
		if _, err := x509.ParseCertificates(rootCA.Asn1); err != nil {
			return nil, err
		}

		rootCAs = append(rootCAs, &common.Certificate{
			DerBytes: rootCA.Asn1,
		})
	}

	return rootCAs, nil
}

func parseJWTAuthorities(keys []*types.JWTKey) ([]*common.PublicKey, error) {
	var jwtKeys []*common.PublicKey
	for _, key := range keys {
		if _, err := x509.ParsePKIXPublicKey(key.PublicKey); err != nil {
			return nil, err
		}

		if key.KeyId == "" {
			return nil, errors.New("missing KeyId")
		}

		jwtKeys = append(jwtKeys, &common.PublicKey{
			PkixBytes: key.PublicKey,
			Kid:       key.KeyId,
			NotAfter:  key.ExpiresAt,
		})
	}

	return jwtKeys, nil
}

func (s *Service) PublishJWTAuthority(ctx context.Context, req *bundle.PublishJWTAuthorityRequest) (*bundle.PublishJWTAuthorityResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PublishJWTAuthority not implemented")
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
			}).Errorf("Bundle has an invalid trust domain ID")
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
	return nil, status.Errorf(codes.Unimplemented, "method BatchCreateFederatedBundle not implemented")
}

func (s *Service) BatchUpdateFederatedBundle(ctx context.Context, req *bundle.BatchUpdateFederatedBundleRequest) (*bundle.BatchUpdateFederatedBundleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method BatchUpdateFederatedBundle not implemented")
}

func (s *Service) BatchSetFederatedBundle(ctx context.Context, req *bundle.BatchSetFederatedBundleRequest) (*bundle.BatchSetFederatedBundleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method BatchSetFederatedBundle not implemented")
}

func (s *Service) BatchDeleteFederatedBundle(ctx context.Context, req *bundle.BatchDeleteFederatedBundleRequest) (*bundle.BatchDeleteFederatedBundleResponse, error) {
	var results []*bundle.BatchDeleteFederatedBundleResponse_Result
	for _, trustDomain := range req.TrustDomains {
		err := s.deleteFederatedBundle(ctx, trustDomain)
		results = append(results, &bundle.BatchDeleteFederatedBundleResponse_Result{
			Status:      api.StatusFromError(err),
			TrustDomain: trustDomain,
		})
	}

	return &bundle.BatchDeleteFederatedBundleResponse{
		Results: results,
	}, nil
}

func (s *Service) deleteFederatedBundle(ctx context.Context, trustDomain string) error {
	log := rpccontext.Logger(ctx).WithField(telemetry.TrustDomainID, trustDomain)

	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		log.WithError(err).Error("Invalid request: malformed trust domain")
		return status.Errorf(codes.InvalidArgument, "malformed trust domain: %v", err)
	}

	if s.td.Compare(td) == 0 {
		log.Error("Invalid request: removing the bundle for the server trust domain is not allowed")
		return status.Error(codes.InvalidArgument, "removing the bundle for the server trust domain is not allowed")
	}

	_, err = s.ds.DeleteBundle(ctx, &datastore.DeleteBundleRequest{
		TrustDomainId: td.String(),
		// TODO: what mode must we use here?
		Mode: datastore.DeleteBundleRequest_RESTRICT,
	})
	if err != nil {
		log.WithError(err).Error("Failed to delete federated bundle")
		return status.Errorf(codes.Internal, "failed to delete federated bundle: %v", err)
	}

	return nil
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
