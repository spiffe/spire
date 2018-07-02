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

// Plugin is the interface implemented by plugin implementations
type Plugin interface {
	SignCsr(context.Context, *SignCsrRequest) (*SignCsrResponse, error)
	GenerateCsr(context.Context, *GenerateCsrRequest) (*GenerateCsrResponse, error)
	FetchCertificate(context.Context, *FetchCertificateRequest) (*FetchCertificateResponse, error)
	LoadCertificate(context.Context, *LoadCertificateRequest) (*LoadCertificateResponse, error)
	Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error)
	GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error)
}

type BuiltIn struct {
	plugin Plugin
}

var _ ServerCA = (*BuiltIn)(nil)

func NewBuiltIn(plugin Plugin) *BuiltIn {
	return &BuiltIn{
		plugin: plugin,
	}
}

func (b BuiltIn) SignCsr(ctx context.Context, req *SignCsrRequest) (*SignCsrResponse, error) {
	resp, err := b.plugin.SignCsr(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) GenerateCsr(ctx context.Context, req *GenerateCsrRequest) (*GenerateCsrResponse, error) {
	resp, err := b.plugin.GenerateCsr(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) FetchCertificate(ctx context.Context, req *FetchCertificateRequest) (*FetchCertificateResponse, error) {
	resp, err := b.plugin.FetchCertificate(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) LoadCertificate(ctx context.Context, req *LoadCertificateRequest) (*LoadCertificateResponse, error) {
	resp, err := b.plugin.LoadCertificate(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
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
	MagicCookieKey:   "ServerCA",
	MagicCookieValue: "ServerCA",
}

type GRPCPlugin struct {
	ServerImpl ServerCAServer
}

func (p GRPCPlugin) Server(*go_plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p GRPCPlugin) Client(b *go_plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p GRPCPlugin) GRPCServer(s *grpc.Server) error {
	RegisterServerCAServer(s, p.ServerImpl)
	return nil
}

func (p GRPCPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewServerCAClient(c)}, nil
}

type GRPCServer struct {
	Plugin Plugin
}

func (s *GRPCServer) SignCsr(ctx context.Context, req *SignCsrRequest) (*SignCsrResponse, error) {
	return s.Plugin.SignCsr(ctx, req)
}
func (s *GRPCServer) GenerateCsr(ctx context.Context, req *GenerateCsrRequest) (*GenerateCsrResponse, error) {
	return s.Plugin.GenerateCsr(ctx, req)
}
func (s *GRPCServer) FetchCertificate(ctx context.Context, req *FetchCertificateRequest) (*FetchCertificateResponse, error) {
	return s.Plugin.FetchCertificate(ctx, req)
}
func (s *GRPCServer) LoadCertificate(ctx context.Context, req *LoadCertificateRequest) (*LoadCertificateResponse, error) {
	return s.Plugin.LoadCertificate(ctx, req)
}
func (s *GRPCServer) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return s.Plugin.Configure(ctx, req)
}
func (s *GRPCServer) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return s.Plugin.GetPluginInfo(ctx, req)
}

type GRPCClient struct {
	client ServerCAClient
}

func (c *GRPCClient) SignCsr(ctx context.Context, req *SignCsrRequest) (*SignCsrResponse, error) {
	return c.client.SignCsr(ctx, req)
}
func (c *GRPCClient) GenerateCsr(ctx context.Context, req *GenerateCsrRequest) (*GenerateCsrResponse, error) {
	return c.client.GenerateCsr(ctx, req)
}
func (c *GRPCClient) FetchCertificate(ctx context.Context, req *FetchCertificateRequest) (*FetchCertificateResponse, error) {
	return c.client.FetchCertificate(ctx, req)
}
func (c *GRPCClient) LoadCertificate(ctx context.Context, req *LoadCertificateRequest) (*LoadCertificateResponse, error) {
	return c.client.LoadCertificate(ctx, req)
}
func (c *GRPCClient) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return c.client.Configure(ctx, req)
}
func (c *GRPCClient) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return c.client.GetPluginInfo(ctx, req)
}
