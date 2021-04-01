// Provides interfaces and adapters for the MetricsService service
//
// Generated code. Do not modify by hand.
package hostservices

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	metricsv0 "github.com/spiffe/spire/proto/spire/hostservice/common/metrics/v0"
	"google.golang.org/grpc"
)

type AddSampleRequest = metricsv0.AddSampleRequest                                   //nolint: golint
type AddSampleResponse = metricsv0.AddSampleResponse                                 //nolint: golint
type EmitKeyRequest = metricsv0.EmitKeyRequest                                       //nolint: golint
type EmitKeyResponse = metricsv0.EmitKeyResponse                                     //nolint: golint
type IncrCounterRequest = metricsv0.IncrCounterRequest                               //nolint: golint
type IncrCounterResponse = metricsv0.IncrCounterResponse                             //nolint: golint
type Label = metricsv0.Label                                                         //nolint: golint
type MeasureSinceRequest = metricsv0.MeasureSinceRequest                             //nolint: golint
type MeasureSinceResponse = metricsv0.MeasureSinceResponse                           //nolint: golint
type MetricsServiceClient = metricsv0.MetricsServiceClient                           //nolint: golint
type MetricsServiceServer = metricsv0.MetricsServiceServer                           //nolint: golint
type SetGaugeRequest = metricsv0.SetGaugeRequest                                     //nolint: golint
type SetGaugeResponse = metricsv0.SetGaugeResponse                                   //nolint: golint
type UnimplementedMetricsServiceServer = metricsv0.UnimplementedMetricsServiceServer //nolint: golint
type UnsafeMetricsServiceServer = metricsv0.UnsafeMetricsServiceServer               //nolint: golint

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
	metricsv0.RegisterMetricsServiceServer(server, s.server)
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

func (c *metricsServiceHostServiceClient) InitHostServiceClient(conn grpc.ClientConnInterface) {
	*c.client = AdaptMetricsServiceHostServiceClient(metricsv0.NewMetricsServiceClient(conn))
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
