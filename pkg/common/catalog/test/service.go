// Provides interfaces and adapters for the Service service
//
// Generated code. Do not modify by hand.
package test

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc"
)

const (
	ServiceType = "Service"
)

// Service is the client interface for the service type Service interface.
type Service interface {
	CallService(context.Context, *Request) (*Response, error)
}

// ServiceServiceServer returns a catalog ServiceServer implementation for the Service plugin.
func ServiceServiceServer(server ServiceServer) catalog.ServiceServer {
	return &serviceServiceServer{
		server: server,
	}
}

type serviceServiceServer struct {
	server ServiceServer
}

func (s serviceServiceServer) ServiceType() string {
	return ServiceType
}

func (s serviceServiceServer) ServiceClient() catalog.ServiceClient {
	return ServiceServiceClient
}

func (s serviceServiceServer) RegisterServiceServer(server *grpc.Server) interface{} {
	RegisterServiceServer(server, s.server)
	return s.server
}

// ServiceServiceClient is a catalog ServiceClient implementation for the Service plugin.
var ServiceServiceClient catalog.ServiceClient = serviceServiceClient{}

type serviceServiceClient struct{}

func (serviceServiceClient) ServiceType() string {
	return ServiceType
}

func (serviceServiceClient) NewServiceClient(conn *grpc.ClientConn) interface{} {
	return AdaptServiceServiceClient(NewServiceClient(conn))
}

func AdaptServiceServiceClient(client ServiceClient) Service {
	return serviceServiceClientAdapter{client: client}
}

type serviceServiceClientAdapter struct {
	client ServiceClient
}

func (a serviceServiceClientAdapter) CallService(ctx context.Context, in *Request) (*Response, error) {
	return a.client.CallService(ctx, in)
}
