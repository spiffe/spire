package node

import (
	"context"

	"github.com/spiffe/sri/control_plane/api/node/proto"
)

// Implement yor service methods methods.
// e.x: Foo(ctx context.Context,s string)(rs string, err error)
type NodeService interface {
	FetchBaseSVID(ctx context.Context, request control_plane_proto.FetchBaseSVIDRequest) (response control_plane_proto.FetchBaseSVIDResponse)
	FetchSVID(ctx context.Context, request control_plane_proto.FetchSVIDRequest) (response control_plane_proto.FetchSVIDResponse)
	FetchCPBundle(ctx context.Context, request control_plane_proto.FetchCPBundleRequest) (response control_plane_proto.FetchCPBundleResponse)
	FetchFederatedBundle(ctx context.Context, request control_plane_proto.FetchFederatedBundleRequest) (response control_plane_proto.FetchFederatedBundleResponse)
}

type stubNodeService struct{}

// Get a new instance of the service.
// If you want to add service middleware this is the place to put them.
func NewService() (s *stubNodeService) {
	s = &stubNodeService{}
	return s
}

// Implement the business logic of FetchBaseSVID
func (no *stubNodeService) FetchBaseSVID(ctx context.Context, request control_plane_proto.FetchBaseSVIDRequest) (response control_plane_proto.FetchBaseSVIDResponse) {
	return response
}

// Implement the business logic of FetchSVID
func (no *stubNodeService) FetchSVID(ctx context.Context, request control_plane_proto.FetchSVIDRequest) (response control_plane_proto.FetchSVIDResponse) {
	return response
}

// Implement the business logic of FetchCPBundle
func (no *stubNodeService) FetchCPBundle(ctx context.Context, request control_plane_proto.FetchCPBundleRequest) (response control_plane_proto.FetchCPBundleResponse) {
	return response
}

// Implement the business logic of FetchFederatedBundle
func (no *stubNodeService) FetchFederatedBundle(ctx context.Context, request control_plane_proto.FetchFederatedBundleRequest) (response control_plane_proto.FetchFederatedBundleResponse) {
	return response
}
