package datastore

import (
	"context"
	"net/rpc"

	"github.com/golang/protobuf/ptypes/empty"
	go_plugin "github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/common/plugin"
	"google.golang.org/grpc"
)

// DataStore is the interface used by all non-catalog components.
type DataStore interface {
	CreateBundle(context.Context, *Bundle) (*Bundle, error)
	UpdateBundle(context.Context, *Bundle) (*Bundle, error)
	AppendBundle(context.Context, *Bundle) (*Bundle, error)
	DeleteBundle(context.Context, *Bundle) (*Bundle, error)
	FetchBundle(context.Context, *Bundle) (*Bundle, error)
	ListBundles(context.Context, *common.Empty) (*Bundles, error)
	CreateAttestedNodeEntry(context.Context, *CreateAttestedNodeEntryRequest) (*CreateAttestedNodeEntryResponse, error)
	FetchAttestedNodeEntry(context.Context, *FetchAttestedNodeEntryRequest) (*FetchAttestedNodeEntryResponse, error)
	FetchStaleNodeEntries(context.Context, *FetchStaleNodeEntriesRequest) (*FetchStaleNodeEntriesResponse, error)
	UpdateAttestedNodeEntry(context.Context, *UpdateAttestedNodeEntryRequest) (*UpdateAttestedNodeEntryResponse, error)
	DeleteAttestedNodeEntry(context.Context, *DeleteAttestedNodeEntryRequest) (*DeleteAttestedNodeEntryResponse, error)
	CreateNodeResolverMapEntry(context.Context, *CreateNodeResolverMapEntryRequest) (*CreateNodeResolverMapEntryResponse, error)
	FetchNodeResolverMapEntry(context.Context, *FetchNodeResolverMapEntryRequest) (*FetchNodeResolverMapEntryResponse, error)
	DeleteNodeResolverMapEntry(context.Context, *DeleteNodeResolverMapEntryRequest) (*DeleteNodeResolverMapEntryResponse, error)
	RectifyNodeResolverMapEntries(context.Context, *RectifyNodeResolverMapEntriesRequest) (*RectifyNodeResolverMapEntriesResponse, error)
	CreateRegistrationEntry(context.Context, *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error)
	FetchRegistrationEntry(context.Context, *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error)
	FetchRegistrationEntries(context.Context, *common.Empty) (*FetchRegistrationEntriesResponse, error)
	UpdateRegistrationEntry(context.Context, *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error)
	DeleteRegistrationEntry(context.Context, *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error)
	ListParentIDEntries(context.Context, *ListParentIDEntriesRequest) (*ListParentIDEntriesResponse, error)
	ListSelectorEntries(context.Context, *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error)
	ListMatchingEntries(context.Context, *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error)
	ListSpiffeEntries(context.Context, *ListSpiffeEntriesRequest) (*ListSpiffeEntriesResponse, error)
	RegisterToken(context.Context, *JoinToken) (*common.Empty, error)
	FetchToken(context.Context, *JoinToken) (*JoinToken, error)
	DeleteToken(context.Context, *JoinToken) (*common.Empty, error)
	PruneTokens(context.Context, *JoinToken) (*common.Empty, error)
}

// Plugin is the interface implemented by plugin implementations
type Plugin interface {
	CreateBundle(context.Context, *Bundle) (*Bundle, error)
	UpdateBundle(context.Context, *Bundle) (*Bundle, error)
	AppendBundle(context.Context, *Bundle) (*Bundle, error)
	DeleteBundle(context.Context, *Bundle) (*Bundle, error)
	FetchBundle(context.Context, *Bundle) (*Bundle, error)
	ListBundles(context.Context, *common.Empty) (*Bundles, error)
	CreateAttestedNodeEntry(context.Context, *CreateAttestedNodeEntryRequest) (*CreateAttestedNodeEntryResponse, error)
	FetchAttestedNodeEntry(context.Context, *FetchAttestedNodeEntryRequest) (*FetchAttestedNodeEntryResponse, error)
	FetchStaleNodeEntries(context.Context, *FetchStaleNodeEntriesRequest) (*FetchStaleNodeEntriesResponse, error)
	UpdateAttestedNodeEntry(context.Context, *UpdateAttestedNodeEntryRequest) (*UpdateAttestedNodeEntryResponse, error)
	DeleteAttestedNodeEntry(context.Context, *DeleteAttestedNodeEntryRequest) (*DeleteAttestedNodeEntryResponse, error)
	CreateNodeResolverMapEntry(context.Context, *CreateNodeResolverMapEntryRequest) (*CreateNodeResolverMapEntryResponse, error)
	FetchNodeResolverMapEntry(context.Context, *FetchNodeResolverMapEntryRequest) (*FetchNodeResolverMapEntryResponse, error)
	DeleteNodeResolverMapEntry(context.Context, *DeleteNodeResolverMapEntryRequest) (*DeleteNodeResolverMapEntryResponse, error)
	RectifyNodeResolverMapEntries(context.Context, *RectifyNodeResolverMapEntriesRequest) (*RectifyNodeResolverMapEntriesResponse, error)
	CreateRegistrationEntry(context.Context, *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error)
	FetchRegistrationEntry(context.Context, *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error)
	FetchRegistrationEntries(context.Context, *common.Empty) (*FetchRegistrationEntriesResponse, error)
	UpdateRegistrationEntry(context.Context, *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error)
	DeleteRegistrationEntry(context.Context, *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error)
	ListParentIDEntries(context.Context, *ListParentIDEntriesRequest) (*ListParentIDEntriesResponse, error)
	ListSelectorEntries(context.Context, *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error)
	ListMatchingEntries(context.Context, *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error)
	ListSpiffeEntries(context.Context, *ListSpiffeEntriesRequest) (*ListSpiffeEntriesResponse, error)
	RegisterToken(context.Context, *JoinToken) (*common.Empty, error)
	FetchToken(context.Context, *JoinToken) (*JoinToken, error)
	DeleteToken(context.Context, *JoinToken) (*common.Empty, error)
	PruneTokens(context.Context, *JoinToken) (*common.Empty, error)
	Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error)
	GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error)
}

type BuiltIn struct {
	plugin Plugin
}

var _ DataStore = (*BuiltIn)(nil)

func NewBuiltIn(plugin Plugin) *BuiltIn {
	return &BuiltIn{
		plugin: plugin,
	}
}

func (b BuiltIn) CreateBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	resp, err := b.plugin.CreateBundle(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) UpdateBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	resp, err := b.plugin.UpdateBundle(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) AppendBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	resp, err := b.plugin.AppendBundle(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) DeleteBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	resp, err := b.plugin.DeleteBundle(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) FetchBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	resp, err := b.plugin.FetchBundle(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) ListBundles(ctx context.Context, req *common.Empty) (*Bundles, error) {
	resp, err := b.plugin.ListBundles(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) CreateAttestedNodeEntry(ctx context.Context, req *CreateAttestedNodeEntryRequest) (*CreateAttestedNodeEntryResponse, error) {
	resp, err := b.plugin.CreateAttestedNodeEntry(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) FetchAttestedNodeEntry(ctx context.Context, req *FetchAttestedNodeEntryRequest) (*FetchAttestedNodeEntryResponse, error) {
	resp, err := b.plugin.FetchAttestedNodeEntry(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) FetchStaleNodeEntries(ctx context.Context, req *FetchStaleNodeEntriesRequest) (*FetchStaleNodeEntriesResponse, error) {
	resp, err := b.plugin.FetchStaleNodeEntries(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) UpdateAttestedNodeEntry(ctx context.Context, req *UpdateAttestedNodeEntryRequest) (*UpdateAttestedNodeEntryResponse, error) {
	resp, err := b.plugin.UpdateAttestedNodeEntry(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) DeleteAttestedNodeEntry(ctx context.Context, req *DeleteAttestedNodeEntryRequest) (*DeleteAttestedNodeEntryResponse, error) {
	resp, err := b.plugin.DeleteAttestedNodeEntry(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) CreateNodeResolverMapEntry(ctx context.Context, req *CreateNodeResolverMapEntryRequest) (*CreateNodeResolverMapEntryResponse, error) {
	resp, err := b.plugin.CreateNodeResolverMapEntry(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) FetchNodeResolverMapEntry(ctx context.Context, req *FetchNodeResolverMapEntryRequest) (*FetchNodeResolverMapEntryResponse, error) {
	resp, err := b.plugin.FetchNodeResolverMapEntry(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) DeleteNodeResolverMapEntry(ctx context.Context, req *DeleteNodeResolverMapEntryRequest) (*DeleteNodeResolverMapEntryResponse, error) {
	resp, err := b.plugin.DeleteNodeResolverMapEntry(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) RectifyNodeResolverMapEntries(ctx context.Context, req *RectifyNodeResolverMapEntriesRequest) (*RectifyNodeResolverMapEntriesResponse, error) {
	resp, err := b.plugin.RectifyNodeResolverMapEntries(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) CreateRegistrationEntry(ctx context.Context, req *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error) {
	resp, err := b.plugin.CreateRegistrationEntry(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) FetchRegistrationEntry(ctx context.Context, req *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error) {
	resp, err := b.plugin.FetchRegistrationEntry(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) FetchRegistrationEntries(ctx context.Context, req *common.Empty) (*FetchRegistrationEntriesResponse, error) {
	resp, err := b.plugin.FetchRegistrationEntries(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) UpdateRegistrationEntry(ctx context.Context, req *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error) {
	resp, err := b.plugin.UpdateRegistrationEntry(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) DeleteRegistrationEntry(ctx context.Context, req *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error) {
	resp, err := b.plugin.DeleteRegistrationEntry(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) ListParentIDEntries(ctx context.Context, req *ListParentIDEntriesRequest) (*ListParentIDEntriesResponse, error) {
	resp, err := b.plugin.ListParentIDEntries(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) ListSelectorEntries(ctx context.Context, req *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error) {
	resp, err := b.plugin.ListSelectorEntries(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) ListMatchingEntries(ctx context.Context, req *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error) {
	resp, err := b.plugin.ListMatchingEntries(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) ListSpiffeEntries(ctx context.Context, req *ListSpiffeEntriesRequest) (*ListSpiffeEntriesResponse, error) {
	resp, err := b.plugin.ListSpiffeEntries(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) RegisterToken(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	resp, err := b.plugin.RegisterToken(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) FetchToken(ctx context.Context, req *JoinToken) (*JoinToken, error) {
	resp, err := b.plugin.FetchToken(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) DeleteToken(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	resp, err := b.plugin.DeleteToken(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) PruneTokens(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	resp, err := b.plugin.PruneTokens(ctx, req)
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
	MagicCookieKey:   "DataStore",
	MagicCookieValue: "DataStore",
}

type GRPCPlugin struct {
	ServerImpl DataStoreServer
}

func (p GRPCPlugin) Server(*go_plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p GRPCPlugin) Client(b *go_plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p GRPCPlugin) GRPCServer(s *grpc.Server) error {
	RegisterDataStoreServer(s, p.ServerImpl)
	return nil
}

func (p GRPCPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewDataStoreClient(c)}, nil
}

type GRPCServer struct {
	Plugin Plugin
}

func (s *GRPCServer) CreateBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return s.Plugin.CreateBundle(ctx, req)
}
func (s *GRPCServer) UpdateBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return s.Plugin.UpdateBundle(ctx, req)
}
func (s *GRPCServer) AppendBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return s.Plugin.AppendBundle(ctx, req)
}
func (s *GRPCServer) DeleteBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return s.Plugin.DeleteBundle(ctx, req)
}
func (s *GRPCServer) FetchBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return s.Plugin.FetchBundle(ctx, req)
}
func (s *GRPCServer) ListBundles(ctx context.Context, req *common.Empty) (*Bundles, error) {
	return s.Plugin.ListBundles(ctx, req)
}
func (s *GRPCServer) CreateAttestedNodeEntry(ctx context.Context, req *CreateAttestedNodeEntryRequest) (*CreateAttestedNodeEntryResponse, error) {
	return s.Plugin.CreateAttestedNodeEntry(ctx, req)
}
func (s *GRPCServer) FetchAttestedNodeEntry(ctx context.Context, req *FetchAttestedNodeEntryRequest) (*FetchAttestedNodeEntryResponse, error) {
	return s.Plugin.FetchAttestedNodeEntry(ctx, req)
}
func (s *GRPCServer) FetchStaleNodeEntries(ctx context.Context, req *FetchStaleNodeEntriesRequest) (*FetchStaleNodeEntriesResponse, error) {
	return s.Plugin.FetchStaleNodeEntries(ctx, req)
}
func (s *GRPCServer) UpdateAttestedNodeEntry(ctx context.Context, req *UpdateAttestedNodeEntryRequest) (*UpdateAttestedNodeEntryResponse, error) {
	return s.Plugin.UpdateAttestedNodeEntry(ctx, req)
}
func (s *GRPCServer) DeleteAttestedNodeEntry(ctx context.Context, req *DeleteAttestedNodeEntryRequest) (*DeleteAttestedNodeEntryResponse, error) {
	return s.Plugin.DeleteAttestedNodeEntry(ctx, req)
}
func (s *GRPCServer) CreateNodeResolverMapEntry(ctx context.Context, req *CreateNodeResolverMapEntryRequest) (*CreateNodeResolverMapEntryResponse, error) {
	return s.Plugin.CreateNodeResolverMapEntry(ctx, req)
}
func (s *GRPCServer) FetchNodeResolverMapEntry(ctx context.Context, req *FetchNodeResolverMapEntryRequest) (*FetchNodeResolverMapEntryResponse, error) {
	return s.Plugin.FetchNodeResolverMapEntry(ctx, req)
}
func (s *GRPCServer) DeleteNodeResolverMapEntry(ctx context.Context, req *DeleteNodeResolverMapEntryRequest) (*DeleteNodeResolverMapEntryResponse, error) {
	return s.Plugin.DeleteNodeResolverMapEntry(ctx, req)
}
func (s *GRPCServer) RectifyNodeResolverMapEntries(ctx context.Context, req *RectifyNodeResolverMapEntriesRequest) (*RectifyNodeResolverMapEntriesResponse, error) {
	return s.Plugin.RectifyNodeResolverMapEntries(ctx, req)
}
func (s *GRPCServer) CreateRegistrationEntry(ctx context.Context, req *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error) {
	return s.Plugin.CreateRegistrationEntry(ctx, req)
}
func (s *GRPCServer) FetchRegistrationEntry(ctx context.Context, req *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error) {
	return s.Plugin.FetchRegistrationEntry(ctx, req)
}
func (s *GRPCServer) FetchRegistrationEntries(ctx context.Context, req *common.Empty) (*FetchRegistrationEntriesResponse, error) {
	return s.Plugin.FetchRegistrationEntries(ctx, req)
}
func (s *GRPCServer) UpdateRegistrationEntry(ctx context.Context, req *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error) {
	return s.Plugin.UpdateRegistrationEntry(ctx, req)
}
func (s *GRPCServer) DeleteRegistrationEntry(ctx context.Context, req *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error) {
	return s.Plugin.DeleteRegistrationEntry(ctx, req)
}
func (s *GRPCServer) ListParentIDEntries(ctx context.Context, req *ListParentIDEntriesRequest) (*ListParentIDEntriesResponse, error) {
	return s.Plugin.ListParentIDEntries(ctx, req)
}
func (s *GRPCServer) ListSelectorEntries(ctx context.Context, req *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error) {
	return s.Plugin.ListSelectorEntries(ctx, req)
}
func (s *GRPCServer) ListMatchingEntries(ctx context.Context, req *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error) {
	return s.Plugin.ListMatchingEntries(ctx, req)
}
func (s *GRPCServer) ListSpiffeEntries(ctx context.Context, req *ListSpiffeEntriesRequest) (*ListSpiffeEntriesResponse, error) {
	return s.Plugin.ListSpiffeEntries(ctx, req)
}
func (s *GRPCServer) RegisterToken(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	return s.Plugin.RegisterToken(ctx, req)
}
func (s *GRPCServer) FetchToken(ctx context.Context, req *JoinToken) (*JoinToken, error) {
	return s.Plugin.FetchToken(ctx, req)
}
func (s *GRPCServer) DeleteToken(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	return s.Plugin.DeleteToken(ctx, req)
}
func (s *GRPCServer) PruneTokens(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	return s.Plugin.PruneTokens(ctx, req)
}
func (s *GRPCServer) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return s.Plugin.Configure(ctx, req)
}
func (s *GRPCServer) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return s.Plugin.GetPluginInfo(ctx, req)
}

type GRPCClient struct {
	client DataStoreClient
}

func (c *GRPCClient) CreateBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return c.client.CreateBundle(ctx, req)
}
func (c *GRPCClient) UpdateBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return c.client.UpdateBundle(ctx, req)
}
func (c *GRPCClient) AppendBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return c.client.AppendBundle(ctx, req)
}
func (c *GRPCClient) DeleteBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return c.client.DeleteBundle(ctx, req)
}
func (c *GRPCClient) FetchBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return c.client.FetchBundle(ctx, req)
}
func (c *GRPCClient) ListBundles(ctx context.Context, req *common.Empty) (*Bundles, error) {
	return c.client.ListBundles(ctx, req)
}
func (c *GRPCClient) CreateAttestedNodeEntry(ctx context.Context, req *CreateAttestedNodeEntryRequest) (*CreateAttestedNodeEntryResponse, error) {
	return c.client.CreateAttestedNodeEntry(ctx, req)
}
func (c *GRPCClient) FetchAttestedNodeEntry(ctx context.Context, req *FetchAttestedNodeEntryRequest) (*FetchAttestedNodeEntryResponse, error) {
	return c.client.FetchAttestedNodeEntry(ctx, req)
}
func (c *GRPCClient) FetchStaleNodeEntries(ctx context.Context, req *FetchStaleNodeEntriesRequest) (*FetchStaleNodeEntriesResponse, error) {
	return c.client.FetchStaleNodeEntries(ctx, req)
}
func (c *GRPCClient) UpdateAttestedNodeEntry(ctx context.Context, req *UpdateAttestedNodeEntryRequest) (*UpdateAttestedNodeEntryResponse, error) {
	return c.client.UpdateAttestedNodeEntry(ctx, req)
}
func (c *GRPCClient) DeleteAttestedNodeEntry(ctx context.Context, req *DeleteAttestedNodeEntryRequest) (*DeleteAttestedNodeEntryResponse, error) {
	return c.client.DeleteAttestedNodeEntry(ctx, req)
}
func (c *GRPCClient) CreateNodeResolverMapEntry(ctx context.Context, req *CreateNodeResolverMapEntryRequest) (*CreateNodeResolverMapEntryResponse, error) {
	return c.client.CreateNodeResolverMapEntry(ctx, req)
}
func (c *GRPCClient) FetchNodeResolverMapEntry(ctx context.Context, req *FetchNodeResolverMapEntryRequest) (*FetchNodeResolverMapEntryResponse, error) {
	return c.client.FetchNodeResolverMapEntry(ctx, req)
}
func (c *GRPCClient) DeleteNodeResolverMapEntry(ctx context.Context, req *DeleteNodeResolverMapEntryRequest) (*DeleteNodeResolverMapEntryResponse, error) {
	return c.client.DeleteNodeResolverMapEntry(ctx, req)
}
func (c *GRPCClient) RectifyNodeResolverMapEntries(ctx context.Context, req *RectifyNodeResolverMapEntriesRequest) (*RectifyNodeResolverMapEntriesResponse, error) {
	return c.client.RectifyNodeResolverMapEntries(ctx, req)
}
func (c *GRPCClient) CreateRegistrationEntry(ctx context.Context, req *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error) {
	return c.client.CreateRegistrationEntry(ctx, req)
}
func (c *GRPCClient) FetchRegistrationEntry(ctx context.Context, req *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error) {
	return c.client.FetchRegistrationEntry(ctx, req)
}
func (c *GRPCClient) FetchRegistrationEntries(ctx context.Context, req *common.Empty) (*FetchRegistrationEntriesResponse, error) {
	return c.client.FetchRegistrationEntries(ctx, req)
}
func (c *GRPCClient) UpdateRegistrationEntry(ctx context.Context, req *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error) {
	return c.client.UpdateRegistrationEntry(ctx, req)
}
func (c *GRPCClient) DeleteRegistrationEntry(ctx context.Context, req *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error) {
	return c.client.DeleteRegistrationEntry(ctx, req)
}
func (c *GRPCClient) ListParentIDEntries(ctx context.Context, req *ListParentIDEntriesRequest) (*ListParentIDEntriesResponse, error) {
	return c.client.ListParentIDEntries(ctx, req)
}
func (c *GRPCClient) ListSelectorEntries(ctx context.Context, req *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error) {
	return c.client.ListSelectorEntries(ctx, req)
}
func (c *GRPCClient) ListMatchingEntries(ctx context.Context, req *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error) {
	return c.client.ListMatchingEntries(ctx, req)
}
func (c *GRPCClient) ListSpiffeEntries(ctx context.Context, req *ListSpiffeEntriesRequest) (*ListSpiffeEntriesResponse, error) {
	return c.client.ListSpiffeEntries(ctx, req)
}
func (c *GRPCClient) RegisterToken(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	return c.client.RegisterToken(ctx, req)
}
func (c *GRPCClient) FetchToken(ctx context.Context, req *JoinToken) (*JoinToken, error) {
	return c.client.FetchToken(ctx, req)
}
func (c *GRPCClient) DeleteToken(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	return c.client.DeleteToken(ctx, req)
}
func (c *GRPCClient) PruneTokens(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	return c.client.PruneTokens(ctx, req)
}
func (c *GRPCClient) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return c.client.Configure(ctx, req)
}
func (c *GRPCClient) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return c.client.GetPluginInfo(ctx, req)
}
