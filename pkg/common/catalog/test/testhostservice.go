// Provides interfaces and adapters for the TestHostService service
//
// Generated code. Do not modify by hand.
package test

import (
	"context"

	catalog "github.com/spiffe/spire/pkg/common/catalog/internal"
	"google.golang.org/grpc"
)

const (
	TestHostServiceType = "TestHostService"
)

// TestHostService is the client interface for the service type TestHostService interface.
type TestHostService interface {
	CallHostService(context.Context, *Request) (*Response, error)
}

// TestHostServiceHostServiceServer returns a catalog HostServiceServer implementation for the TestHostService plugin.
func TestHostServiceHostServiceServer(server TestHostServiceServer) catalog.HostServiceServer {
	return &testHostServiceHostServiceServer{
		server: server,
	}
}

type testHostServiceHostServiceServer struct {
	server TestHostServiceServer
}

func (s testHostServiceHostServiceServer) HostServiceType() string {
	return TestHostServiceType
}

func (s testHostServiceHostServiceServer) RegisterHostServiceServer(server *grpc.Server) {
	RegisterTestHostServiceServer(server, s.server)
}

// TestHostServiceHostServiceServer returns a catalog HostServiceServer implementation for the TestHostService plugin.
func TestHostServiceHostServiceClient(client *TestHostService) catalog.HostServiceClient {
	return &testHostServiceHostServiceClient{
		client: client,
	}
}

type testHostServiceHostServiceClient struct {
	client *TestHostService
}

func (c *testHostServiceHostServiceClient) HostServiceType() string {
	return TestHostServiceType
}

func (c *testHostServiceHostServiceClient) InitHostServiceClient(conn *grpc.ClientConn) {
	*c.client = AdaptTestHostServiceHostServiceClient(NewTestHostServiceClient(conn))
}

func AdaptTestHostServiceHostServiceClient(client TestHostServiceClient) TestHostService {
	return testHostServiceHostServiceClientAdapter{client: client}
}

type testHostServiceHostServiceClientAdapter struct {
	client TestHostServiceClient
}

func (a testHostServiceHostServiceClientAdapter) CallHostService(ctx context.Context, in *Request) (*Response, error) {
	return a.client.CallHostService(ctx, in)
}
