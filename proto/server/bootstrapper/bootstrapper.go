package bootstrapper

import (
	"context"
	"net/rpc"

	"github.com/golang/protobuf/ptypes/empty"
	go_plugin "github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/proto/builtin"
	"github.com/spiffe/spire/proto/common/plugin"
	"google.golang.org/grpc"
)

// Bootstrapper is the interface used by all non-catalog components.
type Bootstrapper interface {
	PublishBundle(context.Context) (PublishBundle_Stream, error)
}

// Plugin is the interface implemented by plugin implementations
type Plugin interface {
	PublishBundle(PublishBundle_PluginStream) error
	Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error)
	GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error)
}

type PublishBundle_Stream interface {
	Context() context.Context
	Send(*PublishBundleRequest) error
	Recv() (*PublishBundleResponse, error)
	CloseSend() error
}

type publishBundle_Stream struct {
	stream builtin.BidiStreamClient
}

func (s publishBundle_Stream) Context() context.Context {
	return s.stream.Context()
}

func (s publishBundle_Stream) Send(m *PublishBundleRequest) error {
	return s.stream.Send(m)
}

func (s publishBundle_Stream) Recv() (*PublishBundleResponse, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.(*PublishBundleResponse), nil
}

func (s publishBundle_Stream) CloseSend() error {
	return s.stream.CloseSend()
}

type PublishBundle_PluginStream interface {
	Context() context.Context
	Send(*PublishBundleResponse) error
	Recv() (*PublishBundleRequest, error)
}

type publishBundle_PluginStream struct {
	stream builtin.BidiStreamServer
}

func (s publishBundle_PluginStream) Context() context.Context {
	return s.stream.Context()
}

func (s publishBundle_PluginStream) Send(m *PublishBundleResponse) error {
	return s.stream.Send(m)
}

func (s publishBundle_PluginStream) Recv() (*PublishBundleRequest, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.(*PublishBundleRequest), nil
}

type BuiltIn struct {
	plugin Plugin
}

var _ Bootstrapper = (*BuiltIn)(nil)

func NewBuiltIn(plugin Plugin) *BuiltIn {
	return &BuiltIn{
		plugin: plugin,
	}
}

func (b BuiltIn) PublishBundle(ctx context.Context) (PublishBundle_Stream, error) {
	clientStream, serverStream := builtin.BidiStreamPipe(ctx)
	go func() {
		serverStream.Close(b.plugin.PublishBundle(publishBundle_PluginStream{stream: serverStream}))
	}()
	return publishBundle_Stream{stream: clientStream}, nil
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
	MagicCookieKey:   "Bootstrapper",
	MagicCookieValue: "Bootstrapper",
}

type GRPCPlugin struct {
	ServerImpl BootstrapperServer
}

func (p GRPCPlugin) Server(*go_plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p GRPCPlugin) Client(b *go_plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p GRPCPlugin) GRPCServer(s *grpc.Server) error {
	RegisterBootstrapperServer(s, p.ServerImpl)
	return nil
}

func (p GRPCPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewBootstrapperClient(c)}, nil
}

type GRPCServer struct {
	Plugin Plugin
}

func (s *GRPCServer) PublishBundle(stream Bootstrapper_PublishBundleServer) error {
	return s.Plugin.PublishBundle(stream)
}
func (s *GRPCServer) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return s.Plugin.Configure(ctx, req)
}
func (s *GRPCServer) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return s.Plugin.GetPluginInfo(ctx, req)
}

type GRPCClient struct {
	client BootstrapperClient
}

func (c *GRPCClient) PublishBundle(ctx context.Context) (PublishBundle_Stream, error) {
	return c.client.PublishBundle(ctx)
}
func (c *GRPCClient) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return c.client.Configure(ctx, req)
}
func (c *GRPCClient) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return c.client.GetPluginInfo(ctx, req)
}
