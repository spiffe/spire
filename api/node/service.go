package node

import (
	"context"
	"github.com/spiffe/control-plane/api/node/pb"
)

// Implement yor service methods methods.
// e.x: Foo(ctx context.Context,s string)(rs string, err error)
type NodeService interface {
	FetchBootstrapSVID(ctx context.Context, request pb.FetchBootstrapSVIDRequest) (response pb.FetchBootstrapSVIDResponse)
	FetchNodeSVID(ctx context.Context, request pb.FetchNodeSVIDRequest) (response pb.FetchBootstrapSVIDResponse)
	FetchSVID(ctx context.Context, request pb.FetchSVIDRequest) (response pb.FetchSVIDResponse)
	FetchCPBundle(ctx context.Context, request pb.FetchCPBundleRequest) (response pb.FetchCPBundleResponse)
}

type stubNodeService struct{}

// Get a new instance of the service.
// If you want to add service middleware this is the place to put them.
func NewService() (s *stubNodeService) {
	s = &stubNodeService{}
	return s
}

// Implement the business logic of FetchBootstrapSVID
func (no *stubNodeService) FetchBootstrapSVID(ctx context.Context, request pb.FetchBootstrapSVIDRequest) (response pb.FetchBootstrapSVIDResponse) {
	return response
}

// Implement the business logic of FetchNodeSVID
func (no *stubNodeService) FetchNodeSVID(ctx context.Context, request pb.FetchNodeSVIDRequest) (response pb.FetchBootstrapSVIDResponse) {
	return response
}

// Implement the business logic of FetchSVID
func (no *stubNodeService) FetchSVID(ctx context.Context, request pb.FetchSVIDRequest) (response pb.FetchSVIDResponse) {
	return response
}

// Implement the business logic of FetchCPBundle
func (no *stubNodeService) FetchCPBundle(ctx context.Context, request pb.FetchCPBundleRequest) (response pb.FetchCPBundleResponse) {
	return response
}
