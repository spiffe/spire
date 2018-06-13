package workloadattestor

import (
	"context"
	"net/rpc"

	"github.com/golang/protobuf/ptypes/empty"
	go_plugin "github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/proto/common/plugin"
	"google.golang.org/grpc"
)

// WorkloadAttestor is the interface used by all non-catalog components.
type WorkloadAttestor interface {
	Attest(context.Context, *AttestRequest) (*AttestResponse, error)
}

// WorkloadAttestor is the interface implemented by plugin implementations
type WorkloadAttestorPlugin interface {
	Attest(context.Context, *AttestRequest) (*AttestResponse, error)
	Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error)
	GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error)
}

type WorkloadAttestorBuiltIn struct {
	plugin WorkloadAttestorPlugin
}

var _ WorkloadAttestor = (*WorkloadAttestorBuiltIn)(nil)

func NewWorkloadAttestorBuiltIn(plugin WorkloadAttestorPlugin) *WorkloadAttestorBuiltIn {
	return &WorkloadAttestorBuiltIn{
		plugin: plugin,
	}
}

func (b WorkloadAttestorBuiltIn) Attest(ctx context.Context, req *AttestRequest) (*AttestResponse, error) {
	return b.plugin.Attest(ctx, req)
}

func (b WorkloadAttestorBuiltIn) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return b.plugin.Configure(ctx, req)
}

func (b WorkloadAttestorBuiltIn) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return b.plugin.GetPluginInfo(ctx, req)
}

var Handshake = go_plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "WorkloadAttestor",
	MagicCookieValue: "WorkloadAttestor",
}

type WorkloadAttestorGRPCPlugin struct {
	ServerImpl WorkloadAttestorServer
}

func (p WorkloadAttestorGRPCPlugin) Server(*go_plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p WorkloadAttestorGRPCPlugin) Client(b *go_plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p WorkloadAttestorGRPCPlugin) GRPCServer(s *grpc.Server) error {
	RegisterWorkloadAttestorServer(s, p.ServerImpl)
	return nil
}

func (p WorkloadAttestorGRPCPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &WorkloadAttestorGRPCClient{client: NewWorkloadAttestorClient(c)}, nil
}

type WorkloadAttestorGRPCServer struct {
	Plugin WorkloadAttestorPlugin
}

func (s *WorkloadAttestorGRPCServer) Attest(ctx context.Context, req *AttestRequest) (*AttestResponse, error) {
	return s.Plugin.Attest(ctx, req)
}
func (s *WorkloadAttestorGRPCServer) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return s.Plugin.Configure(ctx, req)
}
func (s *WorkloadAttestorGRPCServer) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return s.Plugin.GetPluginInfo(ctx, req)
}

type WorkloadAttestorGRPCClient struct {
	client WorkloadAttestorClient
}

func (c *WorkloadAttestorGRPCClient) Attest(ctx context.Context, req *AttestRequest) (*AttestResponse, error) {
	return c.client.Attest(ctx, req)
}
func (c *WorkloadAttestorGRPCClient) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return c.client.Configure(ctx, req)
}
func (c *WorkloadAttestorGRPCClient) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return c.client.GetPluginInfo(ctx, req)
}
