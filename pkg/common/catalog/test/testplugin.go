// Provides interfaces and adapters for the TestPlugin service
//
// Generated code. Do not modify by hand.
package test

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog/internal"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"google.golang.org/grpc"
)

const (
	TestPluginType = "TestPlugin"
)

// TestPlugin is the client interface for the service type TestPlugin interface.
type TestPlugin interface {
	CallPlugin(context.Context, *Request) (*Response, error)
}

// TestPluginPlugin is the client interface for the service with the plugin related methods used by the catalog to initialize the plugin.
type TestPluginPlugin interface {
	CallPlugin(context.Context, *Request) (*Response, error)
	Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
}

// TestPluginPluginServer returns a catalog PluginServer implementation for the TestPlugin plugin.
func TestPluginPluginServer(server TestPluginServer) internal.PluginServer {
	return &testPluginPluginServer{
		server: server,
	}
}

type testPluginPluginServer struct {
	server TestPluginServer
}

func (s testPluginPluginServer) PluginType() string {
	return TestPluginType
}

func (s testPluginPluginServer) PluginClient() internal.PluginClient {
	return TestPluginPluginClient
}

func (s testPluginPluginServer) RegisterPluginServer(server *grpc.Server) interface{} {
	RegisterTestPluginServer(server, s.server)
	return s.server
}

// TestPluginPluginClient is a catalog PluginClient implementation for the TestPlugin plugin.
var TestPluginPluginClient internal.PluginClient = testPluginPluginClient{}

type testPluginPluginClient struct{}

func (testPluginPluginClient) PluginType() string {
	return TestPluginType
}

func (testPluginPluginClient) NewPluginClient(conn *grpc.ClientConn) interface{} {
	return AdaptPluginClientTestPlugin(NewTestPluginClient(conn))
}

func AdaptPluginClientTestPlugin(client TestPluginClient) TestPlugin {
	return testPluginPluginClientAdapter{client: client}
}

type testPluginPluginClientAdapter struct {
	client TestPluginClient
}

func (a testPluginPluginClientAdapter) CallPlugin(ctx context.Context, in *Request) (*Response, error) {
	return a.client.CallPlugin(ctx, in)
}

func (a testPluginPluginClientAdapter) Configure(ctx context.Context, in *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return a.client.Configure(ctx, in)
}
