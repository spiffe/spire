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
	Attest(context.Context) (NodeAttestor_Attest_Stream, error)
}

// NodeAttestor is the interface implemented by plugin implementations
type NodeAttestorPlugin interface {
	Attest(NodeAttestor_Attest_PluginStream) error
	Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error)
	GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error)
}

type NodeAttestor_Attest_Stream interface {
	Context() context.Context
	Send(*AttestRequest) error
	Recv() (*AttestResponse, error)
	CloseSend() error
}

type nodeAttestor_Attest_Stream struct {
	stream builtin.BidiStreamClient
}

func (s nodeAttestor_Attest_Stream) Context() context.Context {
	return s.stream.Context()
}

func (s nodeAttestor_Attest_Stream) Send(m *AttestRequest) error {
	return s.stream.Send(m)
}

func (s nodeAttestor_Attest_Stream) Recv() (*AttestResponse, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.(*AttestResponse), nil
}

func (s nodeAttestor_Attest_Stream) CloseSend() error {
	return s.stream.CloseSend()
}

type NodeAttestor_Attest_PluginStream interface {
	Context() context.Context
	Send(*AttestResponse) error
	Recv() (*AttestRequest, error)
}

type nodeAttestor_Attest_PluginStream struct {
	stream builtin.BidiStreamServer
}

func (s nodeAttestor_Attest_PluginStream) Context() context.Context {
	return s.stream.Context()
}

func (s nodeAttestor_Attest_PluginStream) Send(m *AttestResponse) error {
	return s.stream.Send(m)
}

func (s nodeAttestor_Attest_PluginStream) Recv() (*AttestRequest, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.(*AttestRequest), nil
}

type NodeAttestorBuiltIn struct {
	plugin NodeAttestorPlugin
}

var _ NodeAttestor = (*NodeAttestorBuiltIn)(nil)

func NewNodeAttestorBuiltIn(plugin NodeAttestorPlugin) *NodeAttestorBuiltIn {
	return &NodeAttestorBuiltIn{
		plugin: plugin,
	}
}

func (b NodeAttestorBuiltIn) Attest(ctx context.Context) (NodeAttestor_Attest_Stream, error) {
	clientStream, serverStream := builtin.BidiStreamPipe(ctx)
	go func() {
		serverStream.Close(b.plugin.Attest(nodeAttestor_Attest_PluginStream{stream: serverStream}))
	}()
	return nodeAttestor_Attest_Stream{stream: clientStream}, nil
}

func (b NodeAttestorBuiltIn) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return b.plugin.Configure(ctx, req)
}

func (b NodeAttestorBuiltIn) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return b.plugin.GetPluginInfo(ctx, req)
}

var Handshake = go_plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "NodeAttestor",
	MagicCookieValue: "NodeAttestor",
}

type NodeAttestorGRPCPlugin struct {
	ServerImpl NodeAttestorServer
}

func (p NodeAttestorGRPCPlugin) Server(*go_plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p NodeAttestorGRPCPlugin) Client(b *go_plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p NodeAttestorGRPCPlugin) GRPCServer(s *grpc.Server) error {
	RegisterNodeAttestorServer(s, p.ServerImpl)
	return nil
}

func (p NodeAttestorGRPCPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &NodeAttestorGRPCClient{client: NewNodeAttestorClient(c)}, nil
}

type NodeAttestorGRPCServer struct {
	Plugin NodeAttestorPlugin
}

func (s *NodeAttestorGRPCServer) Attest(stream NodeAttestor_AttestServer) error {
	return s.Plugin.Attest(stream)
}
func (s *NodeAttestorGRPCServer) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return s.Plugin.Configure(ctx, req)
}
func (s *NodeAttestorGRPCServer) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return s.Plugin.GetPluginInfo(ctx, req)
}

type NodeAttestorGRPCClient struct {
	client NodeAttestorClient
}

func (c *NodeAttestorGRPCClient) Attest(ctx context.Context) (NodeAttestor_Attest_Stream, error) {
	return c.client.Attest(ctx)
}
func (c *NodeAttestorGRPCClient) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return c.client.Configure(ctx, req)
}
func (c *NodeAttestorGRPCClient) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return c.client.GetPluginInfo(ctx, req)
}
