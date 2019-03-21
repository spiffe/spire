package dummy

import (
	"context"
	"net/rpc"

	"github.com/golang/protobuf/ptypes/empty"
	go_plugin "github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/proto/builtin"
	"github.com/spiffe/spire/proto/common/plugin"
	"google.golang.org/grpc"
)

// Dummy is the interface used by all non-catalog components.
type Dummy interface {
	NoStream(context.Context, *NoStreamRequest) (*NoStreamResponse, error)
	ClientStream(context.Context) (ClientStream_Stream, error)
	ServerStream(context.Context, *ServerStreamRequest) (ServerStream_Stream, error)
	BothStream(context.Context) (BothStream_Stream, error)
}

// Plugin is the interface implemented by plugin implementations
type Plugin interface {
	NoStream(context.Context, *NoStreamRequest) (*NoStreamResponse, error)
	ClientStream(ClientStream_PluginStream) error
	ServerStream(*ServerStreamRequest, ServerStream_PluginStream) error
	BothStream(BothStream_PluginStream) error
	Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error)
	GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error)
}

type ClientStream_Stream interface {
	Context() context.Context
	Send(*ClientStreamRequest) error
	CloseAndRecv() (*ClientStreamResponse, error)
}

type clientStream_Stream struct {
	stream builtin.SendStreamClient
}

func (s clientStream_Stream) Context() context.Context {
	return s.stream.Context()
}

func (s clientStream_Stream) Send(m *ClientStreamRequest) error {
	return s.stream.Send(m)
}

func (s clientStream_Stream) CloseAndRecv() (*ClientStreamResponse, error) {
	m, err := s.stream.CloseAndRecv()
	if err != nil {
		return nil, err
	}
	return m.(*ClientStreamResponse), nil
}

type ClientStream_PluginStream interface {
	Context() context.Context
	SendAndClose(*ClientStreamResponse) error
	Recv() (*ClientStreamRequest, error)
}

type clientStream_PluginStream struct {
	stream builtin.SendStreamServer
}

func (s clientStream_PluginStream) Context() context.Context {
	return s.stream.Context()
}

func (s clientStream_PluginStream) SendAndClose(m *ClientStreamResponse) error {
	return s.stream.SendAndClose(m)
}

func (s clientStream_PluginStream) Recv() (*ClientStreamRequest, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.(*ClientStreamRequest), nil
}

type ServerStream_Stream interface {
	Context() context.Context
	Recv() (*ServerStreamResponse, error)
}

type serverStream_Stream struct {
	stream builtin.RecvStreamClient
}

func (s serverStream_Stream) Context() context.Context {
	return s.stream.Context()
}

func (s serverStream_Stream) Recv() (*ServerStreamResponse, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.(*ServerStreamResponse), nil
}

type ServerStream_PluginStream interface {
	Context() context.Context
	Send(*ServerStreamResponse) error
}

type serverStream_PluginStream struct {
	stream builtin.RecvStreamServer
}

func (s serverStream_PluginStream) Context() context.Context {
	return s.stream.Context()
}

func (s serverStream_PluginStream) Send(m *ServerStreamResponse) error {
	return s.stream.Send(m)
}

type BothStream_Stream interface {
	Context() context.Context
	Send(*BothStreamRequest) error
	Recv() (*BothStreamResponse, error)
	CloseSend() error
}

type bothStream_Stream struct {
	stream builtin.BidiStreamClient
}

func (s bothStream_Stream) Context() context.Context {
	return s.stream.Context()
}

func (s bothStream_Stream) Send(m *BothStreamRequest) error {
	return s.stream.Send(m)
}

func (s bothStream_Stream) Recv() (*BothStreamResponse, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.(*BothStreamResponse), nil
}

func (s bothStream_Stream) CloseSend() error {
	return s.stream.CloseSend()
}

type BothStream_PluginStream interface {
	Context() context.Context
	Send(*BothStreamResponse) error
	Recv() (*BothStreamRequest, error)
}

type bothStream_PluginStream struct {
	stream builtin.BidiStreamServer
}

func (s bothStream_PluginStream) Context() context.Context {
	return s.stream.Context()
}

func (s bothStream_PluginStream) Send(m *BothStreamResponse) error {
	return s.stream.Send(m)
}

func (s bothStream_PluginStream) Recv() (*BothStreamRequest, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.(*BothStreamRequest), nil
}

type BuiltIn struct {
	plugin Plugin
}

var _ Dummy = (*BuiltIn)(nil)

func NewBuiltIn(plugin Plugin) *BuiltIn {
	return &BuiltIn{
		plugin: plugin,
	}
}

func (b BuiltIn) NoStream(ctx context.Context, req *NoStreamRequest) (*NoStreamResponse, error) {
	resp, err := b.plugin.NoStream(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) ClientStream(ctx context.Context) (ClientStream_Stream, error) {
	clientStream, serverStream := builtin.SendStreamPipe(ctx)
	go func() {
		serverStream.Close(b.plugin.ClientStream(clientStream_PluginStream{stream: serverStream}))
	}()
	return clientStream_Stream{stream: clientStream}, nil
}

func (b BuiltIn) ServerStream(ctx context.Context, req *ServerStreamRequest) (ServerStream_Stream, error) {
	clientStream, serverStream := builtin.RecvStreamPipe(ctx)
	go func() {
		serverStream.Close(b.plugin.ServerStream(req, serverStream_PluginStream{stream: serverStream}))
	}()
	return serverStream_Stream{stream: clientStream}, nil
}

func (b BuiltIn) BothStream(ctx context.Context) (BothStream_Stream, error) {
	clientStream, serverStream := builtin.BidiStreamPipe(ctx)
	go func() {
		serverStream.Close(b.plugin.BothStream(bothStream_PluginStream{stream: serverStream}))
	}()
	return bothStream_Stream{stream: clientStream}, nil
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
	MagicCookieKey:   "Dummy",
	MagicCookieValue: "Dummy",
}

type GRPCPlugin struct {
	ServerImpl DummyServer
}

var _ go_plugin.GRPCPlugin = (*GRPCPlugin)(nil)

func (p GRPCPlugin) Server(*go_plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p GRPCPlugin) Client(b *go_plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p GRPCPlugin) GRPCServer(b *go_plugin.GRPCBroker, s *grpc.Server) error {
	RegisterDummyServer(s, p.ServerImpl)
	return nil
}

func (p GRPCPlugin) GRPCClient(ctx context.Context, b *go_plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewDummyClient(c)}, nil
}

type GRPCServer struct {
	Plugin Plugin
}

func (s *GRPCServer) NoStream(ctx context.Context, req *NoStreamRequest) (*NoStreamResponse, error) {
	return s.Plugin.NoStream(ctx, req)
}
func (s *GRPCServer) ClientStream(stream Dummy_ClientStreamServer) error {
	return s.Plugin.ClientStream(stream)
}
func (s *GRPCServer) ServerStream(req *ServerStreamRequest, stream Dummy_ServerStreamServer) error {
	return s.Plugin.ServerStream(req, stream)
}
func (s *GRPCServer) BothStream(stream Dummy_BothStreamServer) error {
	return s.Plugin.BothStream(stream)
}
func (s *GRPCServer) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return s.Plugin.Configure(ctx, req)
}
func (s *GRPCServer) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return s.Plugin.GetPluginInfo(ctx, req)
}

type GRPCClient struct {
	client DummyClient
}

func (c *GRPCClient) NoStream(ctx context.Context, req *NoStreamRequest) (*NoStreamResponse, error) {
	return c.client.NoStream(ctx, req)
}
func (c *GRPCClient) ClientStream(ctx context.Context) (ClientStream_Stream, error) {
	return c.client.ClientStream(ctx)
}
func (c *GRPCClient) ServerStream(ctx context.Context, req *ServerStreamRequest) (ServerStream_Stream, error) {
	return c.client.ServerStream(ctx, req)
}
func (c *GRPCClient) BothStream(ctx context.Context) (BothStream_Stream, error) {
	return c.client.BothStream(ctx)
}
func (c *GRPCClient) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return c.client.Configure(ctx, req)
}
func (c *GRPCClient) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return c.client.GetPluginInfo(ctx, req)
}
