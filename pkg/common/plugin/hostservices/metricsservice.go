// Provides interfaces and adapters for the MetricsService service
//
// Generated code. Do not modify by hand.
package hostservices

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common/hostservices"
	"google.golang.org/grpc"
)

type AddSampleRequest = hostservices.AddSampleRequest                                   //nolint: golint
type AddSampleResponse = hostservices.AddSampleResponse                                 //nolint: golint
type EmitKeyRequest = hostservices.EmitKeyRequest                                       //nolint: golint
type EmitKeyResponse = hostservices.EmitKeyResponse                                     //nolint: golint
type IncrCounterRequest = hostservices.IncrCounterRequest                               //nolint: golint
type IncrCounterResponse = hostservices.IncrCounterResponse                             //nolint: golint
type Label = hostservices.Label                                                         //nolint: golint
type MeasureSinceRequest = hostservices.MeasureSinceRequest                             //nolint: golint
type MeasureSinceResponse = hostservices.MeasureSinceResponse                           //nolint: golint
type MetricsServiceClient = hostservices.MetricsServiceClient                           //nolint: golint
type MetricsServiceServer = hostservices.MetricsServiceServer                           //nolint: golint
type SetGaugeRequest = hostservices.SetGaugeRequest                                     //nolint: golint
type SetGaugeResponse = hostservices.SetGaugeResponse                                   //nolint: golint
type UnimplementedMetricsServiceServer = hostservices.UnimplementedMetricsServiceServer //nolint: golint

const (
	MetricsServiceType = "MetricsService"
)

// MetricsService is the client interface for the service type MetricsService interface.
type MetricsService interface {
	AddSample(context.Context, *AddSampleRequest) (*AddSampleResponse, error)
	EmitKey(context.Context, *EmitKeyRequest) (*EmitKeyResponse, error)
	IncrCounter(context.Context, *IncrCounterRequest) (*IncrCounterResponse, error)
	MeasureSince(context.Context, *MeasureSinceRequest) (*MeasureSinceResponse, error)
	SetGauge(context.Context, *SetGaugeRequest) (*SetGaugeResponse, error)
}

// MetricsServiceHostServiceServer returns a catalog HostServiceServer implementation for the MetricsService plugin.
func MetricsServiceHostServiceServer(server MetricsServiceServer) catalog.HostServiceServer {
	return &metricsServiceHostServiceServer{
		server: server,
	}
}

type metricsServiceHostServiceServer struct {
	server MetricsServiceServer
}

func (s metricsServiceHostServiceServer) HostServiceType() string {
	return MetricsServiceType
}

func (s metricsServiceHostServiceServer) RegisterHostServiceServer(server *grpc.Server) {
	hostservices.RegisterMetricsServiceServer(server, s.server)
}

// MetricsServiceHostServiceServer returns a catalog HostServiceServer implementation for the MetricsService plugin.
func MetricsServiceHostServiceClient(client *MetricsService) catalog.HostServiceClient {
	return &metricsServiceHostServiceClient{
		client: client,
	}
}

type metricsServiceHostServiceClient struct {
	client *MetricsService
}

func (c *metricsServiceHostServiceClient) HostServiceType() string {
	return MetricsServiceType
}

func (c *metricsServiceHostServiceClient) InitHostServiceClient(conn *grpc.ClientConn) {
	*c.client = AdaptMetricsServiceHostServiceClient(hostservices.NewMetricsServiceClient(conn))
}

func AdaptMetricsServiceHostServiceClient(client MetricsServiceClient) MetricsService {
	return metricsServiceHostServiceClientAdapter{client: client}
}

type metricsServiceHostServiceClientAdapter struct {
	client MetricsServiceClient
}

func (a metricsServiceHostServiceClientAdapter) AddSample(ctx context.Context, in *AddSampleRequest) (*AddSampleResponse, error) {
	return a.client.AddSample(ctx, in)
}

func (a metricsServiceHostServiceClientAdapter) EmitKey(ctx context.Context, in *EmitKeyRequest) (*EmitKeyResponse, error) {
	return a.client.EmitKey(ctx, in)
}

func (a metricsServiceHostServiceClientAdapter) IncrCounter(ctx context.Context, in *IncrCounterRequest) (*IncrCounterResponse, error) {
	return a.client.IncrCounter(ctx, in)
}

func (a metricsServiceHostServiceClientAdapter) MeasureSince(ctx context.Context, in *MeasureSinceRequest) (*MeasureSinceResponse, error) {
	return a.client.MeasureSince(ctx, in)
}

func (a metricsServiceHostServiceClientAdapter) SetGauge(ctx context.Context, in *SetGaugeRequest) (*SetGaugeResponse, error) {
	return a.client.SetGauge(ctx, in)
}
