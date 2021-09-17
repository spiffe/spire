package trustdomain

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/datastore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

// Config is the service configuration.
type Config struct {
	DataStore   datastore.DataStore
	TrustDomain spiffeid.TrustDomain
}

// Service implements the v1 trustdomain service.
type Service struct {
	trustdomainv1.UnsafeTrustDomainServer

	ds datastore.DataStore
	td spiffeid.TrustDomain
}

// New creates a new trustdomain service.
func New(config Config) *Service {
	return &Service{
		ds: config.DataStore,
		td: config.TrustDomain,
	}
}

// RegisterService registers the trustdomain service on the gRPC server.
func RegisterService(s *grpc.Server, service *Service) {
	trustdomainv1.RegisterTrustDomainServer(s, service)
}

func (s *Service) ListFederationRelationships(ctx context.Context, req *trustdomainv1.ListFederationRelationshipsRequest) (*trustdomainv1.ListFederationRelationshipsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) GetFederationRelationship(ctx context.Context, req *trustdomainv1.GetFederationRelationshipRequest) (*types.FederationRelationship, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) BatchCreateFederationRelationship(ctx context.Context, req *trustdomainv1.BatchCreateFederationRelationshipRequest) (*trustdomainv1.BatchCreateFederationRelationshipResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) BatchUpdateFederationRelationship(ctx context.Context, req *trustdomainv1.BatchUpdateFederationRelationshipRequest) (*trustdomainv1.BatchUpdateFederationRelationshipResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) BatchDeleteFederationRelationship(ctx context.Context, req *trustdomainv1.BatchDeleteFederationRelationshipRequest) (*trustdomainv1.BatchDeleteFederationRelationshipResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) RefreshBundle(ctx context.Context, req *trustdomainv1.RefreshBundleRequest) (*emptypb.Empty, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}
