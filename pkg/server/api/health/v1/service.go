package health

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/datastore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// RegisterService registers the service on the gRPC server.
func RegisterService(s *grpc.Server, service *Service) {
	grpc_health_v1.RegisterHealthServer(s, service)
}

// Config is the service configuration
type Config struct {
	TrustDomain spiffeid.TrustDomain
	DataStore   datastore.DataStore
}

// New creates a new Health service
func New(config Config) *Service {
	return &Service{
		ds: config.DataStore,
		td: config.TrustDomain,
	}
}

// Service implements the v1 Health service
type Service struct {
	grpc_health_v1.UnimplementedHealthServer

	ds datastore.DataStore
	td spiffeid.TrustDomain
}

func (s *Service) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	log := rpccontext.Logger(ctx)

	// Ensure per-service health is not being requested.
	if req.Service != "" {
		return nil, api.MakeErr(log, codes.InvalidArgument, "per-service health is not supported", nil)
	}

	bundle, err := s.ds.FetchBundle(ctx, s.td.IDString())

	var unhealthyReason string
	switch {
	case err != nil:
		log = log.WithError(err)
		unhealthyReason = "unable to fetch bundle"
	case bundle == nil:
		unhealthyReason = "bundle is missing"
	}

	healthStatus := grpc_health_v1.HealthCheckResponse_SERVING
	if unhealthyReason != "" {
		healthStatus = grpc_health_v1.HealthCheckResponse_NOT_SERVING
		log.WithField(telemetry.Reason, unhealthyReason).Warn("Health check failed")
	}

	return &grpc_health_v1.HealthCheckResponse{
		Status: healthStatus,
	}, nil
}
