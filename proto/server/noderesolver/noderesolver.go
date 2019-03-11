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

// Plugin is the interface implemented by plugin implementations
type Plugin interface {
	Resolve(context.Context, *ResolveRequest) (*ResolveResponse, error)
	Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error)
	GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error)
}

type BuiltIn struct {
	plugin Plugin
}

var _ NodeResolver = (*BuiltIn)(nil)

func NewBuiltIn(plugin Plugin) *BuiltIn {
	return &BuiltIn{
		plugin: plugin,
	}
}

func (b BuiltIn) Resolve(ctx context.Context, req *ResolveRequest) (*ResolveResponse, error) {
	resp, err := b.plugin.Resolve(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	resp, err := b.plugin.Configure(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	resp, err := b.plugin.GetPluginInfo(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

var Handshake = go_plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "NodeResolver",
	MagicCookieValue: "NodeResolver",
}

type GRPCPlugin struct {
	ServerImpl NodeResolverServer
}

var _ go_plugin.GRPCPlugin = (*GRPCPlugin)(nil)

func (p GRPCPlugin) Server(*go_plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p GRPCPlugin) Client(b *go_plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p GRPCPlugin) GRPCServer(b *go_plugin.GRPCBroker, s *grpc.Server) error {
	RegisterNodeResolverServer(s, p.ServerImpl)
	return nil
}

func (p GRPCPlugin) GRPCClient(ctx context.Context, b *go_plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewNodeResolverClient(c)}, nil
}

type GRPCServer struct {
	Plugin Plugin
}

func (s *GRPCServer) Resolve(ctx context.Context, req *ResolveRequest) (*ResolveResponse, error) {
	return s.Plugin.Resolve(ctx, req)
}
func (s *GRPCServer) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return s.Plugin.Configure(ctx, req)
}
func (s *GRPCServer) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return s.Plugin.GetPluginInfo(ctx, req)
}

type GRPCClient struct {
	client NodeResolverClient
}

func (c *GRPCClient) Resolve(ctx context.Context, req *ResolveRequest) (*ResolveResponse, error) {
	return c.client.Resolve(ctx, req)
}
func (c *GRPCClient) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return c.client.Configure(ctx, req)
}
func (c *GRPCClient) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return c.client.GetPluginInfo(ctx, req)
}
