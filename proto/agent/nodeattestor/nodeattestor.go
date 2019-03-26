package nodeattestor

import (
	"context"
	"net/rpc"

	"github.com/golang/protobuf/ptypes/empty"
	go_plugin "github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/proto/builtin"
	"github.com/spiffe/spire/proto/common/plugin"
	"google.golang.org/grpc"
)

// NodeAttestor is the interface used by all non-catalog components.
type NodeAttestor interface {
	FetchAttestationData(context.Context) (FetchAttestationData_Stream, error)
}

// Plugin is the interface implemented by plugin implementations
type Plugin interface {
	FetchAttestationData(FetchAttestationData_PluginStream) error
	Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error)
	GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error)
}

type FetchAttestationData_Stream interface {
	Context() context.Context
	Send(*FetchAttestationDataRequest) error
	Recv() (*FetchAttestationDataResponse, error)
	CloseSend() error
}

type fetchAttestationData_Stream struct {
	stream builtin.BidiStreamClient
}

func (s fetchAttestationData_Stream) Context() context.Context {
	return s.stream.Context()
}

func (s fetchAttestationData_Stream) Send(m *FetchAttestationDataRequest) error {
	return s.stream.Send(m)
}

func (s fetchAttestationData_Stream) Recv() (*FetchAttestationDataResponse, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.(*FetchAttestationDataResponse), nil
}

func (s fetchAttestationData_Stream) CloseSend() error {
	return s.stream.CloseSend()
}

type FetchAttestationData_PluginStream interface {
	Context() context.Context
	Send(*FetchAttestationDataResponse) error
	Recv() (*FetchAttestationDataRequest, error)
}

type fetchAttestationData_PluginStream struct {
	stream builtin.BidiStreamServer
}

func (s fetchAttestationData_PluginStream) Context() context.Context {
	return s.stream.Context()
}

func (s fetchAttestationData_PluginStream) Send(m *FetchAttestationDataResponse) error {
	return s.stream.Send(m)
}

func (s fetchAttestationData_PluginStream) Recv() (*FetchAttestationDataRequest, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.(*FetchAttestationDataRequest), nil
}

type BuiltIn struct {
	plugin Plugin
}

var _ NodeAttestor = (*BuiltIn)(nil)

func NewBuiltIn(plugin Plugin) *BuiltIn {
	return &BuiltIn{
		plugin: plugin,
	}
}

func (b BuiltIn) FetchAttestationData(ctx context.Context) (FetchAttestationData_Stream, error) {
	clientStream, serverStream := builtin.BidiStreamPipe(ctx)
	go func() {
		serverStream.Close(b.plugin.FetchAttestationData(fetchAttestationData_PluginStream{stream: serverStream}))
	}()
	return fetchAttestationData_Stream{stream: clientStream}, nil
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
	MagicCookieKey:   "NodeAttestor",
	MagicCookieValue: "NodeAttestor",
}

type GRPCPlugin struct {
	ServerImpl NodeAttestorServer
}

var _ go_plugin.GRPCPlugin = (*GRPCPlugin)(nil)

func (p GRPCPlugin) Server(*go_plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p GRPCPlugin) Client(b *go_plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p GRPCPlugin) GRPCServer(b *go_plugin.GRPCBroker, s *grpc.Server) error {
	RegisterNodeAttestorServer(s, p.ServerImpl)
	return nil
}

func (p GRPCPlugin) GRPCClient(ctx context.Context, b *go_plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewNodeAttestorClient(c)}, nil
}

type GRPCServer struct {
	Plugin Plugin
}

func (s *GRPCServer) FetchAttestationData(stream NodeAttestor_FetchAttestationDataServer) error {
	return s.Plugin.FetchAttestationData(stream)
}
func (s *GRPCServer) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return s.Plugin.Configure(ctx, req)
}
func (s *GRPCServer) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return s.Plugin.GetPluginInfo(ctx, req)
}

type GRPCClient struct {
	client NodeAttestorClient
}

func (c *GRPCClient) FetchAttestationData(ctx context.Context) (FetchAttestationData_Stream, error) {
	return c.client.FetchAttestationData(ctx)
}
func (c *GRPCClient) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return c.client.Configure(ctx, req)
}
func (c *GRPCClient) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return c.client.GetPluginInfo(ctx, req)
}
