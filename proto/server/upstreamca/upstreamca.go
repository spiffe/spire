package upstreamca

import (
	"context"
	"net/rpc"

	"github.com/golang/protobuf/ptypes/empty"
	go_plugin "github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/proto/common/plugin"
	"google.golang.org/grpc"
)

// UpstreamCA is the interface used by all non-catalog components.
type UpstreamCA interface {
	SubmitCSR(context.Context, *SubmitCSRRequest) (*SubmitCSRResponse, error)
}

// UpstreamCA is the interface implemented by plugin implementations
type UpstreamCAPlugin interface {
	Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error)
	GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error)
	SubmitCSR(context.Context, *SubmitCSRRequest) (*SubmitCSRResponse, error)
}

type UpstreamCABuiltIn struct {
	plugin UpstreamCAPlugin
}

var _ UpstreamCA = (*UpstreamCABuiltIn)(nil)

func NewUpstreamCABuiltIn(plugin UpstreamCAPlugin) *UpstreamCABuiltIn {
	return &UpstreamCABuiltIn{
		plugin: plugin,
	}
}

func (b UpstreamCABuiltIn) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return b.plugin.Configure(ctx, req)
}

func (b UpstreamCABuiltIn) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return b.plugin.GetPluginInfo(ctx, req)
}

func (b UpstreamCABuiltIn) SubmitCSR(ctx context.Context, req *SubmitCSRRequest) (*SubmitCSRResponse, error) {
	return b.plugin.SubmitCSR(ctx, req)
}

var Handshake = go_plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "UpstreamCA",
	MagicCookieValue: "UpstreamCA",
}

type UpstreamCAGRPCPlugin struct {
	ServerImpl UpstreamCAServer
}

func (p UpstreamCAGRPCPlugin) Server(*go_plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p UpstreamCAGRPCPlugin) Client(b *go_plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p UpstreamCAGRPCPlugin) GRPCServer(s *grpc.Server) error {
	RegisterUpstreamCAServer(s, p.ServerImpl)
	return nil
}

func (p UpstreamCAGRPCPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &UpstreamCAGRPCClient{client: NewUpstreamCAClient(c)}, nil
}

type UpstreamCAGRPCServer struct {
	Plugin UpstreamCAPlugin
}

func (s *UpstreamCAGRPCServer) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return s.Plugin.Configure(ctx, req)
}
func (s *UpstreamCAGRPCServer) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return s.Plugin.GetPluginInfo(ctx, req)
}
func (s *UpstreamCAGRPCServer) SubmitCSR(ctx context.Context, req *SubmitCSRRequest) (*SubmitCSRResponse, error) {
	return s.Plugin.SubmitCSR(ctx, req)
}

type UpstreamCAGRPCClient struct {
	client UpstreamCAClient
}

func (c *UpstreamCAGRPCClient) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return c.client.Configure(ctx, req)
}
func (c *UpstreamCAGRPCClient) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return c.client.GetPluginInfo(ctx, req)
}
func (c *UpstreamCAGRPCClient) SubmitCSR(ctx context.Context, req *SubmitCSRRequest) (*SubmitCSRResponse, error) {
	return c.client.SubmitCSR(ctx, req)
}
