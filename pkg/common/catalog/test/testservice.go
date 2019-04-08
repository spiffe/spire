// Provides interfaces and adapters for the TestService service
//
// Generated code. Do not modify by hand.
package test

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog/internal"
	"google.golang.org/grpc"
)

const (
	TestServiceType = "TestService"
)

// TestService is the client interface for the service type TestService interface.
type TestService interface {
	CallService(context.Context, *Request) (*Response, error)
}

// TestServiceServiceServer returns a catalog ServiceServer implementation for the TestService plugin.
func TestServiceServiceServer(server TestServiceServer) internal.ServiceServer {
	return &testServiceServiceServer{
		server: server,
	}
}

type testServiceServiceServer struct {
	server TestServiceServer
}

func (s testServiceServiceServer) ServiceType() string {
	return TestServiceType
}

func (s testServiceServiceServer) ServiceClient() internal.ServiceClient {
	return TestServiceServiceClient
}

func (s testServiceServiceServer) RegisterServiceServer(server *grpc.Server) interface{} {
	RegisterTestServiceServer(server, s.server)
	return s.server
}

// TestServiceServiceClient is a catalog ServiceClient implementation for the TestService plugin.
var TestServiceServiceClient internal.ServiceClient = testServiceServiceClient{}

type testServiceServiceClient struct{}

func (testServiceServiceClient) ServiceType() string {
	return TestServiceType
}

func (testServiceServiceClient) NewServiceClient(conn *grpc.ClientConn) interface{} {
	return AdaptServiceClientTestService(NewTestServiceClient(conn))
}

func AdaptServiceClientTestService(client TestServiceClient) TestService {
	return testServiceServiceClientAdapter{client: client}
}

type testServiceServiceClientAdapter struct {
	client TestServiceClient
}

func (a testServiceServiceClientAdapter) CallService(ctx context.Context, in *Request) (*Response, error) {
	return a.client.CallService(ctx, in)
}
