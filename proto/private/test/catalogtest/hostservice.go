// Provides interfaces and adapters for the HostService service
//
// Generated code. Do not modify by hand.
package catalogtest

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc"
)

const (
	HostServiceType = "HostService"
)

// HostService is the client interface for the service type HostService interface.
type HostService interface {
	CallHostService(context.Context, *Request) (*Response, error)
}

// HostServiceHostServiceServer returns a catalog HostServiceServer implementation for the HostService plugin.
func HostServiceHostServiceServer(server HostServiceServer) catalog.HostServiceServer {
	return &hostServiceHostServiceServer{
		server: server,
	}
}

type hostServiceHostServiceServer struct {
	server HostServiceServer
}

func (s hostServiceHostServiceServer) HostServiceType() string {
	return HostServiceType
}

func (s hostServiceHostServiceServer) RegisterHostServiceServer(server *grpc.Server) {
	RegisterHostServiceServer(server, s.server)
}

// HostServiceHostServiceServer returns a catalog HostServiceServer implementation for the HostService plugin.
func HostServiceHostServiceClient(client *HostService) catalog.HostServiceClient {
	return &hostServiceHostServiceClient{
		client: client,
	}
}

type hostServiceHostServiceClient struct {
	client *HostService
}

func (c *hostServiceHostServiceClient) HostServiceType() string {
	return HostServiceType
}

func (c *hostServiceHostServiceClient) InitHostServiceClient(conn *grpc.ClientConn) {
	*c.client = AdaptHostServiceHostServiceClient(NewHostServiceClient(conn))
}

func AdaptHostServiceHostServiceClient(client HostServiceClient) HostService {
	return hostServiceHostServiceClientAdapter{client: client}
}

type hostServiceHostServiceClientAdapter struct {
	client HostServiceClient
}

func (a hostServiceHostServiceClientAdapter) CallHostService(ctx context.Context, in *Request) (*Response, error) {
	return a.client.CallHostService(ctx, in)
}
