package workload

import (
	"context"

	pb "github.com/spiffe/sri/pkg/api/workload"
	"github.com/spiffe/sri/pkg/common"
)

//Service for workload api
type Service interface {
	FetchBundles(ctx context.Context, request pb.SpiffeId) (response pb.Bundles, err error)
	FetchAllBundles(ctx context.Context, request common.Empty) (response pb.Bundles, err error)
}

type stubWorkloadService struct{}

//NewService gets a new instance of the service.
func NewService() (s *stubWorkloadService) {
	s = &stubWorkloadService{}
	return s
}

func (wo *stubWorkloadService) FetchBundles(ctx context.Context, request pb.SpiffeId) (response pb.Bundles, err error) {
	return response, err
}

func (wo *stubWorkloadService) FetchAllBundles(ctx context.Context, request common.Empty) (response pb.Bundles, err error) {
	return response, err
}
