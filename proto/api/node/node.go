package node

import (
	"context"
	"net/rpc"

	"github.com/golang/protobuf/ptypes/empty"
	go_plugin "github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/proto/builtin"
	"google.golang.org/grpc"
)

// Node is the interface used by all non-catalog components.
type Node interface {
	Attest(context.Context) (Node_Attest_Stream, error)
	FetchX509SVID(context.Context) (Node_FetchX509SVID_Stream, error)
	FetchFederatedBundle(context.Context, *FetchFederatedBundleRequest) (*FetchFederatedBundleResponse, error)
}

// Node is the interface implemented by plugin implementations
type NodePlugin interface {
	Attest(Node_Attest_PluginStream) error
	FetchX509SVID(Node_FetchX509SVID_PluginStream) error
	FetchFederatedBundle(context.Context, *FetchFederatedBundleRequest) (*FetchFederatedBundleResponse, error)
}

type Node_Attest_Stream interface {
	Context() context.Context
	Send(*AttestRequest) error
	Recv() (*AttestResponse, error)
	CloseSend() error
}

type node_Attest_Stream struct {
	stream builtin.BidiStreamClient
}

func (s node_Attest_Stream) Context() context.Context {
	return s.stream.Context()
}

func (s node_Attest_Stream) Send(m *AttestRequest) error {
	return s.stream.Send(m)
}

func (s node_Attest_Stream) Recv() (*AttestResponse, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.(*AttestResponse), nil
}

func (s node_Attest_Stream) CloseSend() error {
	return s.stream.CloseSend()
}

type Node_Attest_PluginStream interface {
	Context() context.Context
	Send(*AttestResponse) error
	Recv() (*AttestRequest, error)
}

type node_Attest_PluginStream struct {
	stream builtin.BidiStreamServer
}

func (s node_Attest_PluginStream) Context() context.Context {
	return s.stream.Context()
}

func (s node_Attest_PluginStream) Send(m *AttestResponse) error {
	return s.stream.Send(m)
}

func (s node_Attest_PluginStream) Recv() (*AttestRequest, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.(*AttestRequest), nil
}

type Node_FetchX509SVID_Stream interface {
	Context() context.Context
	Send(*FetchX509SVIDRequest) error
	Recv() (*FetchX509SVIDResponse, error)
	CloseSend() error
}

type node_FetchX509SVID_Stream struct {
	stream builtin.BidiStreamClient
}

func (s node_FetchX509SVID_Stream) Context() context.Context {
	return s.stream.Context()
}

func (s node_FetchX509SVID_Stream) Send(m *FetchX509SVIDRequest) error {
	return s.stream.Send(m)
}

func (s node_FetchX509SVID_Stream) Recv() (*FetchX509SVIDResponse, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.(*FetchX509SVIDResponse), nil
}

func (s node_FetchX509SVID_Stream) CloseSend() error {
	return s.stream.CloseSend()
}

type Node_FetchX509SVID_PluginStream interface {
	Context() context.Context
	Send(*FetchX509SVIDResponse) error
	Recv() (*FetchX509SVIDRequest, error)
}

type node_FetchX509SVID_PluginStream struct {
	stream builtin.BidiStreamServer
}

func (s node_FetchX509SVID_PluginStream) Context() context.Context {
	return s.stream.Context()
}

func (s node_FetchX509SVID_PluginStream) Send(m *FetchX509SVIDResponse) error {
	return s.stream.Send(m)
}

func (s node_FetchX509SVID_PluginStream) Recv() (*FetchX509SVIDRequest, error) {
	m, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return m.(*FetchX509SVIDRequest), nil
}

type NodeBuiltIn struct {
	plugin NodePlugin
}

var _ Node = (*NodeBuiltIn)(nil)

func NewNodeBuiltIn(plugin NodePlugin) *NodeBuiltIn {
	return &NodeBuiltIn{
		plugin: plugin,
	}
}

func (b NodeBuiltIn) Attest(ctx context.Context) (Node_Attest_Stream, error) {
	clientStream, serverStream := builtin.BidiStreamPipe(ctx)
	go func() {
		serverStream.Close(b.plugin.Attest(node_Attest_PluginStream{stream: serverStream}))
	}()
	return node_Attest_Stream{stream: clientStream}, nil
}

func (b NodeBuiltIn) FetchX509SVID(ctx context.Context) (Node_FetchX509SVID_Stream, error) {
	clientStream, serverStream := builtin.BidiStreamPipe(ctx)
	go func() {
		serverStream.Close(b.plugin.FetchX509SVID(node_FetchX509SVID_PluginStream{stream: serverStream}))
	}()
	return node_FetchX509SVID_Stream{stream: clientStream}, nil
}

func (b NodeBuiltIn) FetchFederatedBundle(ctx context.Context, req *FetchFederatedBundleRequest) (*FetchFederatedBundleResponse, error) {
	return b.plugin.FetchFederatedBundle(ctx, req)
}

var Handshake = go_plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "Node",
	MagicCookieValue: "Node",
}

type NodeGRPCPlugin struct {
	ServerImpl NodeServer
}

func (p NodeGRPCPlugin) Server(*go_plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p NodeGRPCPlugin) Client(b *go_plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p NodeGRPCPlugin) GRPCServer(s *grpc.Server) error {
	RegisterNodeServer(s, p.ServerImpl)
	return nil
}

func (p NodeGRPCPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &NodeGRPCClient{client: NewNodeClient(c)}, nil
}

type NodeGRPCServer struct {
	Plugin NodePlugin
}

func (s *NodeGRPCServer) Attest(stream Node_AttestServer) error {
	return s.Plugin.Attest(stream)
}
func (s *NodeGRPCServer) FetchX509SVID(stream Node_FetchX509SVIDServer) error {
	return s.Plugin.FetchX509SVID(stream)
}
func (s *NodeGRPCServer) FetchFederatedBundle(ctx context.Context, req *FetchFederatedBundleRequest) (*FetchFederatedBundleResponse, error) {
	return s.Plugin.FetchFederatedBundle(ctx, req)
}

type NodeGRPCClient struct {
	client NodeClient
}

func (c *NodeGRPCClient) Attest(ctx context.Context) (Node_Attest_Stream, error) {
	return c.client.Attest(ctx)
}
func (c *NodeGRPCClient) FetchX509SVID(ctx context.Context) (Node_FetchX509SVID_Stream, error) {
	return c.client.FetchX509SVID(ctx)
}
func (c *NodeGRPCClient) FetchFederatedBundle(ctx context.Context, req *FetchFederatedBundleRequest) (*FetchFederatedBundleResponse, error) {
	return c.client.FetchFederatedBundle(ctx, req)
}
