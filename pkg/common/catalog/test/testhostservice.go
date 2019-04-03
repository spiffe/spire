// Provides interfaces and adapters for the TestHostService service
//
// Generated code. Do not modify by hand.
package test

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog/interfaces"
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
func TestHostServiceHostServiceServer(server TestHostServiceServer) interfaces.HostServiceServer {
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
func TestHostServiceHostServiceClient(client *TestHostServiceClient) interfaces.HostServiceClient {
	return &testHostServiceHostServiceClient{
		client: client,
	}
}

type testHostServiceHostServiceClient struct {
	client *TestHostServiceClient
}

func (c *testHostServiceHostServiceClient) HostServiceType() string {
	return TestHostServiceType
}

func (c *testHostServiceHostServiceClient) InitHostServiceClient(conn *grpc.ClientConn) {
	*c.client = NewTestHostServiceClient(conn)
}
