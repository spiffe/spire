package ca

import (
	"context"
	"net/rpc"

	"github.com/golang/protobuf/ptypes/empty"
	go_plugin "github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/proto/common/plugin"
	"google.golang.org/grpc"
)

// ServerCA is the interface used by all non-catalog components.
type ServerCA interface {
	SignCsr(context.Context, *SignCsrRequest) (*SignCsrResponse, error)
	GenerateCsr(context.Context, *GenerateCsrRequest) (*GenerateCsrResponse, error)
	FetchCertificate(context.Context, *FetchCertificateRequest) (*FetchCertificateResponse, error)
	LoadCertificate(context.Context, *LoadCertificateRequest) (*LoadCertificateResponse, error)
}

// ServerCA is the interface implemented by plugin implementations
type ServerCAPlugin interface {
	SignCsr(context.Context, *SignCsrRequest) (*SignCsrResponse, error)
	GenerateCsr(context.Context, *GenerateCsrRequest) (*GenerateCsrResponse, error)
	FetchCertificate(context.Context, *FetchCertificateRequest) (*FetchCertificateResponse, error)
	LoadCertificate(context.Context, *LoadCertificateRequest) (*LoadCertificateResponse, error)
	Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error)
	GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error)
}

type ServerCABuiltIn struct {
	plugin ServerCAPlugin
}

var _ ServerCA = (*ServerCABuiltIn)(nil)

func NewServerCABuiltIn(plugin ServerCAPlugin) *ServerCABuiltIn {
	return &ServerCABuiltIn{
		plugin: plugin,
	}
}

func (b ServerCABuiltIn) SignCsr(ctx context.Context, req *SignCsrRequest) (*SignCsrResponse, error) {
	return b.plugin.SignCsr(ctx, req)
}

func (b ServerCABuiltIn) GenerateCsr(ctx context.Context, req *GenerateCsrRequest) (*GenerateCsrResponse, error) {
	return b.plugin.GenerateCsr(ctx, req)
}

func (b ServerCABuiltIn) FetchCertificate(ctx context.Context, req *FetchCertificateRequest) (*FetchCertificateResponse, error) {
	return b.plugin.FetchCertificate(ctx, req)
}

func (b ServerCABuiltIn) LoadCertificate(ctx context.Context, req *LoadCertificateRequest) (*LoadCertificateResponse, error) {
	return b.plugin.LoadCertificate(ctx, req)
}

func (b ServerCABuiltIn) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return b.plugin.Configure(ctx, req)
}

func (b ServerCABuiltIn) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return b.plugin.GetPluginInfo(ctx, req)
}

var Handshake = go_plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "ServerCA",
	MagicCookieValue: "ServerCA",
}

type ServerCAGRPCPlugin struct {
	ServerImpl ServerCAServer
}

func (p ServerCAGRPCPlugin) Server(*go_plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p ServerCAGRPCPlugin) Client(b *go_plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p ServerCAGRPCPlugin) GRPCServer(s *grpc.Server) error {
	RegisterServerCAServer(s, p.ServerImpl)
	return nil
}

func (p ServerCAGRPCPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &ServerCAGRPCClient{client: NewServerCAClient(c)}, nil
}

type ServerCAGRPCServer struct {
	Plugin ServerCAPlugin
}

func (s *ServerCAGRPCServer) SignCsr(ctx context.Context, req *SignCsrRequest) (*SignCsrResponse, error) {
	return s.Plugin.SignCsr(ctx, req)
}
func (s *ServerCAGRPCServer) GenerateCsr(ctx context.Context, req *GenerateCsrRequest) (*GenerateCsrResponse, error) {
	return s.Plugin.GenerateCsr(ctx, req)
}
func (s *ServerCAGRPCServer) FetchCertificate(ctx context.Context, req *FetchCertificateRequest) (*FetchCertificateResponse, error) {
	return s.Plugin.FetchCertificate(ctx, req)
}
func (s *ServerCAGRPCServer) LoadCertificate(ctx context.Context, req *LoadCertificateRequest) (*LoadCertificateResponse, error) {
	return s.Plugin.LoadCertificate(ctx, req)
}
func (s *ServerCAGRPCServer) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return s.Plugin.Configure(ctx, req)
}
func (s *ServerCAGRPCServer) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return s.Plugin.GetPluginInfo(ctx, req)
}

type ServerCAGRPCClient struct {
	client ServerCAClient
}

func (c *ServerCAGRPCClient) SignCsr(ctx context.Context, req *SignCsrRequest) (*SignCsrResponse, error) {
	return c.client.SignCsr(ctx, req)
}
func (c *ServerCAGRPCClient) GenerateCsr(ctx context.Context, req *GenerateCsrRequest) (*GenerateCsrResponse, error) {
	return c.client.GenerateCsr(ctx, req)
}
func (c *ServerCAGRPCClient) FetchCertificate(ctx context.Context, req *FetchCertificateRequest) (*FetchCertificateResponse, error) {
	return c.client.FetchCertificate(ctx, req)
}
func (c *ServerCAGRPCClient) LoadCertificate(ctx context.Context, req *LoadCertificateRequest) (*LoadCertificateResponse, error) {
	return c.client.LoadCertificate(ctx, req)
}
func (c *ServerCAGRPCClient) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return c.client.Configure(ctx, req)
}
func (c *ServerCAGRPCClient) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return c.client.GetPluginInfo(ctx, req)
}
