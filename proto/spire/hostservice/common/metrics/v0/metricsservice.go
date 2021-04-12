// Provides interfaces and adapters for the MetricsService service
//
// Generated code. Do not modify by hand.
package metricsv0

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc"
)

const (
	Type = "MetricsService"
)

// MetricsService is the client interface for the service type MetricsService interface.
type MetricsService interface {
	AddSample(context.Context, *AddSampleRequest) (*AddSampleResponse, error)
	EmitKey(context.Context, *EmitKeyRequest) (*EmitKeyResponse, error)
	IncrCounter(context.Context, *IncrCounterRequest) (*IncrCounterResponse, error)
	MeasureSince(context.Context, *MeasureSinceRequest) (*MeasureSinceResponse, error)
	SetGauge(context.Context, *SetGaugeRequest) (*SetGaugeResponse, error)
}

// HostServiceServer returns a catalog HostServiceServer implementation for the MetricsService plugin.
func HostServiceServer(server MetricsServiceServer) catalog.HostServiceServer {
	return &hostServiceServer{
		server: server,
	}
}

type hostServiceServer struct {
	server MetricsServiceServer
}

func (s hostServiceServer) HostServiceType() string {
	return Type
}

func (s hostServiceServer) RegisterHostServiceServer(server *grpc.Server) {
	RegisterMetricsServiceServer(server, s.server)
}

// HostServiceServer returns a catalog HostServiceServer implementation for the MetricsService plugin.
func HostServiceClient(client *MetricsService) catalog.HostServiceClient {
	return &hostServiceClient{
		client: client,
	}
}

type hostServiceClient struct {
	client *MetricsService
}

func (c *hostServiceClient) HostServiceType() string {
	return Type
}

func (c *hostServiceClient) InitHostServiceClient(conn grpc.ClientConnInterface) {
	*c.client = AdaptHostServiceClient(NewMetricsServiceClient(conn))
}

func AdaptHostServiceClient(client MetricsServiceClient) MetricsService {
	return hostServiceClientAdapter{client: client}
}

type hostServiceClientAdapter struct {
	client MetricsServiceClient
}

func (a hostServiceClientAdapter) AddSample(ctx context.Context, in *AddSampleRequest) (*AddSampleResponse, error) {
	return a.client.AddSample(ctx, in)
}

func (a hostServiceClientAdapter) EmitKey(ctx context.Context, in *EmitKeyRequest) (*EmitKeyResponse, error) {
	return a.client.EmitKey(ctx, in)
}

func (a hostServiceClientAdapter) IncrCounter(ctx context.Context, in *IncrCounterRequest) (*IncrCounterResponse, error) {
	return a.client.IncrCounter(ctx, in)
}

func (a hostServiceClientAdapter) MeasureSince(ctx context.Context, in *MeasureSinceRequest) (*MeasureSinceResponse, error) {
	return a.client.MeasureSince(ctx, in)
}

func (a hostServiceClientAdapter) SetGauge(ctx context.Context, in *SetGaugeRequest) (*SetGaugeResponse, error) {
	return a.client.SetGauge(ctx, in)
}
