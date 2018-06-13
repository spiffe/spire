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
	FetchAttestationData(context.Context) (NodeAttestor_FetchAttestationData_Stream, error)
}

// NodeAttestor is the interface implemented by plugin implementations
type NodeAttestorPlugin interface {
	FetchAttestationData(NodeAttestor_FetchAttestationData_PluginStream) error
	Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error)
	GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error)
}

type NodeAttestor_FetchAttestationData_Stream interface {
	Context() context.Context
	Send(*FetchAttestationDataRequest) error
	Recv() (*FetchAttestationDataResponse, error)
	CloseSend() error
}

type nodeAttestor_FetchAttestationData_Stream struct {
	stream builtin.BidiStreamClient
}

func (s nodeAttestor_FetchAttestationData_Stream) Context() context.Context {
	return s.stream.Context()
}

func (s nodeAttestor_FetchAttestationData_Stream) Send(m *FetchAttestationDataRequest) error {
	return s.stream.Send(m)
}

func (s nodeAttestor_FetchAttestationData_Stream) Recv() (*FetchAttestationDataResponse, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.(*FetchAttestationDataResponse), nil
}

func (s nodeAttestor_FetchAttestationData_Stream) CloseSend() error {
	return s.stream.CloseSend()
}

type NodeAttestor_FetchAttestationData_PluginStream interface {
	Context() context.Context
	Send(*FetchAttestationDataResponse) error
	Recv() (*FetchAttestationDataRequest, error)
}

type nodeAttestor_FetchAttestationData_PluginStream struct {
	stream builtin.BidiStreamServer
}

func (s nodeAttestor_FetchAttestationData_PluginStream) Context() context.Context {
	return s.stream.Context()
}

func (s nodeAttestor_FetchAttestationData_PluginStream) Send(m *FetchAttestationDataResponse) error {
	return s.stream.Send(m)
}

func (s nodeAttestor_FetchAttestationData_PluginStream) Recv() (*FetchAttestationDataRequest, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.(*FetchAttestationDataRequest), nil
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

func (b NodeAttestorBuiltIn) FetchAttestationData(ctx context.Context) (NodeAttestor_FetchAttestationData_Stream, error) {
	clientStream, serverStream := builtin.BidiStreamPipe(ctx)
	go func() {
		serverStream.Close(b.plugin.FetchAttestationData(nodeAttestor_FetchAttestationData_PluginStream{stream: serverStream}))
	}()
	return nodeAttestor_FetchAttestationData_Stream{stream: clientStream}, nil
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

func (s *NodeAttestorGRPCServer) FetchAttestationData(stream NodeAttestor_FetchAttestationDataServer) error {
	return s.Plugin.FetchAttestationData(stream)
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

func (c *NodeAttestorGRPCClient) FetchAttestationData(ctx context.Context) (NodeAttestor_FetchAttestationData_Stream, error) {
	return c.client.FetchAttestationData(ctx)
}
func (c *NodeAttestorGRPCClient) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return c.client.Configure(ctx, req)
}
func (c *NodeAttestorGRPCClient) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return c.client.GetPluginInfo(ctx, req)
}
