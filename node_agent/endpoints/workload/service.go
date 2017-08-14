package workload

import (
	"context"

	"github.com/spiffe/sri/node_agent/api/workload/pb"
)

// Implement yor service methods methods.
// e.x: Foo(ctx context.Context,s string)(rs string, err error)
type WorkloadService interface {
	FetchSVIDBundle(ctx context.Context, request pb.FetchSVIDBundleRequest) (response pb.FetchSVIDBundleResponse)
	FetchSVIDBundles(ctx context.Context, request pb.Empty) (response pb.FetchSVIDBundlesResponse)
	FetchFederatedBundle(ctx context.Context, request pb.FetchFederatedBundleRequest) (response pb.FetchFederatedBundleResponse)
	FetchFederatedBundles(ctx context.Context, request pb.Empty) (response pb.FetchFederatedBundlesResponse)
}

type stubWorkloadService struct{}

// Get a new instance of the service.
// If you want to add service middleware this is the place to put them.
func NewService() (s *stubWorkloadService) {
	s = &stubWorkloadService{}
	return s
}

// Implement the business logic of FetchSVIDBundle
func (wo *stubWorkloadService) FetchSVIDBundle(ctx context.Context, request pb.FetchSVIDBundleRequest) (response pb.FetchSVIDBundleResponse) {
	return response
}

// Implement the business logic of FetchSVIDBundles
func (wo *stubWorkloadService) FetchSVIDBundles(ctx context.Context, request pb.Empty) (response pb.FetchSVIDBundlesResponse) {
	return response
}

// Implement the business logic of FetchFederatedBundle
func (wo *stubWorkloadService) FetchFederatedBundle(ctx context.Context, request pb.FetchFederatedBundleRequest) (response pb.FetchFederatedBundleResponse) {
	return response
}

// Implement the business logic of FetchFederatedBundles
func (wo *stubWorkloadService) FetchFederatedBundles(ctx context.Context, request pb.Empty) (response pb.FetchFederatedBundlesResponse) {
	return response
}
