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
	ClientStream(context.Context) (Dummy_ClientStream_Stream, error)
	ServerStream(context.Context, *ServerStreamRequest) (Dummy_ServerStream_Stream, error)
	BothStream(context.Context) (Dummy_BothStream_Stream, error)
}

// Dummy is the interface implemented by plugin implementations
type DummyPlugin interface {
	NoStream(context.Context, *NoStreamRequest) (*NoStreamResponse, error)
	ClientStream(Dummy_ClientStream_PluginStream) error
	ServerStream(*ServerStreamRequest, Dummy_ServerStream_PluginStream) error
	BothStream(Dummy_BothStream_PluginStream) error
	Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error)
	GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error)
}

type Dummy_ClientStream_Stream interface {
	Context() context.Context
	Send(*ClientStreamRequest) error
	CloseAndRecv() (*ClientStreamResponse, error)
}

type dummy_ClientStream_Stream struct {
	stream builtin.SendStreamClient
}

func (s dummy_ClientStream_Stream) Context() context.Context {
	return s.stream.Context()
}

func (s dummy_ClientStream_Stream) Send(m *ClientStreamRequest) error {
	return s.stream.Send(m)
}

func (s dummy_ClientStream_Stream) CloseAndRecv() (*ClientStreamResponse, error) {
	m, err := s.stream.CloseAndRecv()
	if err != nil {
		return nil, err
	}
	return m.(*ClientStreamResponse), nil
}

type Dummy_ClientStream_PluginStream interface {
	Context() context.Context
	SendAndClose(*ClientStreamResponse) error
	Recv() (*ClientStreamRequest, error)
}

type dummy_ClientStream_PluginStream struct {
	stream builtin.SendStreamServer
}

func (s dummy_ClientStream_PluginStream) Context() context.Context {
	return s.stream.Context()
}

func (s dummy_ClientStream_PluginStream) SendAndClose(m *ClientStreamResponse) error {
	return s.stream.SendAndClose(m)
}

func (s dummy_ClientStream_PluginStream) Recv() (*ClientStreamRequest, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.(*ClientStreamRequest), nil
}

type Dummy_ServerStream_Stream interface {
	Context() context.Context
	Recv() (*ServerStreamResponse, error)
}

type dummy_ServerStream_Stream struct {
	stream builtin.RecvStreamClient
}

func (s dummy_ServerStream_Stream) Context() context.Context {
	return s.stream.Context()
}

func (s dummy_ServerStream_Stream) Recv() (*ServerStreamResponse, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.(*ServerStreamResponse), nil
}

type Dummy_ServerStream_PluginStream interface {
	Context() context.Context
	Send(*ServerStreamResponse) error
}

type dummy_ServerStream_PluginStream struct {
	stream builtin.RecvStreamServer
}

func (s dummy_ServerStream_PluginStream) Context() context.Context {
	return s.stream.Context()
}

func (s dummy_ServerStream_PluginStream) Send(m *ServerStreamResponse) error {
	return s.stream.Send(m)
}

type Dummy_BothStream_Stream interface {
	Context() context.Context
	Send(*BothStreamRequest) error
	Recv() (*BothStreamResponse, error)
	CloseSend() error
}

type dummy_BothStream_Stream struct {
	stream builtin.BidiStreamClient
}

func (s dummy_BothStream_Stream) Context() context.Context {
	return s.stream.Context()
}

func (s dummy_BothStream_Stream) Send(m *BothStreamRequest) error {
	return s.stream.Send(m)
}

func (s dummy_BothStream_Stream) Recv() (*BothStreamResponse, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.(*BothStreamResponse), nil
}

func (s dummy_BothStream_Stream) CloseSend() error {
	return s.stream.CloseSend()
}

type Dummy_BothStream_PluginStream interface {
	Context() context.Context
	Send(*BothStreamResponse) error
	Recv() (*BothStreamRequest, error)
}

type dummy_BothStream_PluginStream struct {
	stream builtin.BidiStreamServer
}

func (s dummy_BothStream_PluginStream) Context() context.Context {
	return s.stream.Context()
}

func (s dummy_BothStream_PluginStream) Send(m *BothStreamResponse) error {
	return s.stream.Send(m)
}

func (s dummy_BothStream_PluginStream) Recv() (*BothStreamRequest, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.(*BothStreamRequest), nil
}

type DummyBuiltIn struct {
	plugin DummyPlugin
}

var _ Dummy = (*DummyBuiltIn)(nil)

func NewDummyBuiltIn(plugin DummyPlugin) *DummyBuiltIn {
	return &DummyBuiltIn{
		plugin: plugin,
	}
}

func (b DummyBuiltIn) NoStream(ctx context.Context, req *NoStreamRequest) (*NoStreamResponse, error) {
	return b.plugin.NoStream(ctx, req)
}

func (b DummyBuiltIn) ClientStream(ctx context.Context) (Dummy_ClientStream_Stream, error) {
	clientStream, serverStream := builtin.SendStreamPipe(ctx)
	go func() {
		serverStream.Close(b.plugin.ClientStream(dummy_ClientStream_PluginStream{stream: serverStream}))
	}()
	return dummy_ClientStream_Stream{stream: clientStream}, nil
}

func (b DummyBuiltIn) ServerStream(ctx context.Context, req *ServerStreamRequest) (Dummy_ServerStream_Stream, error) {
	clientStream, serverStream := builtin.RecvStreamPipe(ctx)
	go func() {
		serverStream.Close(b.plugin.ServerStream(req, dummy_ServerStream_PluginStream{stream: serverStream}))
	}()
	return dummy_ServerStream_Stream{stream: clientStream}, nil
}

func (b DummyBuiltIn) BothStream(ctx context.Context) (Dummy_BothStream_Stream, error) {
	clientStream, serverStream := builtin.BidiStreamPipe(ctx)
	go func() {
		serverStream.Close(b.plugin.BothStream(dummy_BothStream_PluginStream{stream: serverStream}))
	}()
	return dummy_BothStream_Stream{stream: clientStream}, nil
}

var Handshake = go_plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "Dummy",
	MagicCookieValue: "Dummy",
}

type GRPCPlugin struct {
	ServerImpl DummyServer
}

func (p GRPCPlugin) Server(*go_plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p GRPCPlugin) Client(b *go_plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p GRPCPlugin) GRPCServer(s *grpc.Server) error {
	RegisterDummyServer(s, p.ServerImpl)
	return nil
}

func (p GRPCPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewDummyClient(c)}, nil
}

type GRPCServer struct {
	Plugin DummyPlugin
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

func (c *GRPCClient) ClientStream(ctx context.Context) (Dummy_ClientStream_Stream, error) {
	return c.client.ClientStream(ctx)
}

func (c *GRPCClient) ServerStream(ctx context.Context, req *ServerStreamRequest) (Dummy_ServerStream_Stream, error) {
	return c.client.ServerStream(ctx, req)
}

func (c *GRPCClient) BothStream(ctx context.Context) (Dummy_BothStream_Stream, error) {
	return c.client.BothStream(ctx)
}
