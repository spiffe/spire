package health

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// RegisterService registers the service on the gRPC server.
func RegisterService(s *grpc.Server, service *Service) {
	grpc_health_v1.RegisterHealthServer(s, service)
}

// Config is the service configuration
type Config struct {
	// SocketPath is the Workload API socket path
	SocketPath string
}

// New creates a new Health service
func New(config Config) *Service {
	return &Service{
		socketPath: config.SocketPath,
	}
}

// Service implements the v1 Health service
type Service struct {
	grpc_health_v1.UnimplementedHealthServer

	socketPath string
}

func (s *Service) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	log := rpccontext.Logger(ctx)

	// Ensure per-service health is not being requested.
	if req.Service != "" {
		return nil, api.MakeErr(log, codes.InvalidArgument, "per-service health is not supported", nil)
	}

	_, err := workloadapi.FetchX509Context(ctx, workloadapi.WithAddr("unix://"+s.socketPath))

	healthStatus := grpc_health_v1.HealthCheckResponse_SERVING
	switch status.Code(err) {
	case codes.OK, codes.PermissionDenied:
		// PermissionDenied is ok, since it is likely that the agent will
		// not match workload registrations in most cases. We consider this
		// response healthy.
	default:
		healthStatus = grpc_health_v1.HealthCheckResponse_NOT_SERVING
		log.WithFields(logrus.Fields{
			telemetry.Reason: "unable to fetch X.509 context from Workload API",
			logrus.ErrorKey:  err,
		}).Warn("Health check failed")
	}

	return &grpc_health_v1.HealthCheckResponse{
		Status: healthStatus,
	}, nil
}
