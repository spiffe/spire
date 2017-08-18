package node

import (
	"context"

	"github.com/spiffe/sri/control_plane/api/node/proto"
)

// Implement yor service methods methods.
// e.x: Foo(ctx context.Context,s string)(rs string, err error)
type NodeService interface {
	FetchBaseSVID(ctx context.Context, request sri_proto.FetchBaseSVIDRequest) (response sri_proto.FetchBaseSVIDResponse)
	FetchSVID(ctx context.Context, request sri_proto.FetchSVIDRequest) (response sri_proto.FetchSVIDResponse)
	FetchCPBundle(ctx context.Context, request sri_proto.FetchCPBundleRequest) (response sri_proto.FetchCPBundleResponse)
	FetchFederatedBundle(ctx context.Context, request sri_proto.FetchFederatedBundleRequest) (response sri_proto.FetchFederatedBundleResponse)
}

type stubNodeService struct{}

// Get a new instance of the service.
// If you want to add service middleware this is the place to put them.
func NewService() (s *stubNodeService) {
	s = &stubNodeService{}
	return s
}

// Implement the business logic of FetchBaseSVID
func (no *stubNodeService) FetchBaseSVID(ctx context.Context, request sri_proto.FetchBaseSVIDRequest) (response sri_proto.FetchBaseSVIDResponse) {
	return response
}

// Implement the business logic of FetchSVID
func (no *stubNodeService) FetchSVID(ctx context.Context, request sri_proto.FetchSVIDRequest) (response sri_proto.FetchSVIDResponse) {
	return response
}

// Implement the business logic of FetchCPBundle
func (no *stubNodeService) FetchCPBundle(ctx context.Context, request sri_proto.FetchCPBundleRequest) (response sri_proto.FetchCPBundleResponse) {
	return response
}

// Implement the business logic of FetchFederatedBundle
func (no *stubNodeService) FetchFederatedBundle(ctx context.Context, request sri_proto.FetchFederatedBundleRequest) (response sri_proto.FetchFederatedBundleResponse) {
	return response
}
