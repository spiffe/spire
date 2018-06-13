package noderesolver

import (
	"context"
	"net/rpc"

	"github.com/golang/protobuf/ptypes/empty"
	go_plugin "github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/proto/common/plugin"
	"google.golang.org/grpc"
)

// NodeResolver is the interface used by all non-catalog components.
type NodeResolver interface {
	Resolve(context.Context, *ResolveRequest) (*ResolveResponse, error)
}

// NodeResolver is the interface implemented by plugin implementations
type NodeResolverPlugin interface {
	Resolve(context.Context, *ResolveRequest) (*ResolveResponse, error)
	Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error)
	GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error)
}

type NodeResolverBuiltIn struct {
	plugin NodeResolverPlugin
}

var _ NodeResolver = (*NodeResolverBuiltIn)(nil)

func NewNodeResolverBuiltIn(plugin NodeResolverPlugin) *NodeResolverBuiltIn {
	return &NodeResolverBuiltIn{
		plugin: plugin,
	}
}

func (b NodeResolverBuiltIn) Resolve(ctx context.Context, req *ResolveRequest) (*ResolveResponse, error) {
	return b.plugin.Resolve(ctx, req)
}

func (b NodeResolverBuiltIn) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return b.plugin.Configure(ctx, req)
}

func (b NodeResolverBuiltIn) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return b.plugin.GetPluginInfo(ctx, req)
}

var Handshake = go_plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "NodeResolver",
	MagicCookieValue: "NodeResolver",
}

type NodeResolverGRPCPlugin struct {
	ServerImpl NodeResolverServer
}

func (p NodeResolverGRPCPlugin) Server(*go_plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p NodeResolverGRPCPlugin) Client(b *go_plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p NodeResolverGRPCPlugin) GRPCServer(s *grpc.Server) error {
	RegisterNodeResolverServer(s, p.ServerImpl)
	return nil
}

func (p NodeResolverGRPCPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &NodeResolverGRPCClient{client: NewNodeResolverClient(c)}, nil
}

type NodeResolverGRPCServer struct {
	Plugin NodeResolverPlugin
}

func (s *NodeResolverGRPCServer) Resolve(ctx context.Context, req *ResolveRequest) (*ResolveResponse, error) {
	return s.Plugin.Resolve(ctx, req)
}
func (s *NodeResolverGRPCServer) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return s.Plugin.Configure(ctx, req)
}
func (s *NodeResolverGRPCServer) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return s.Plugin.GetPluginInfo(ctx, req)
}

type NodeResolverGRPCClient struct {
	client NodeResolverClient
}

func (c *NodeResolverGRPCClient) Resolve(ctx context.Context, req *ResolveRequest) (*ResolveResponse, error) {
	return c.client.Resolve(ctx, req)
}
func (c *NodeResolverGRPCClient) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return c.client.Configure(ctx, req)
}
func (c *NodeResolverGRPCClient) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return c.client.GetPluginInfo(ctx, req)
}
