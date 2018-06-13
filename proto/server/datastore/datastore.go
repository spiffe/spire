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

// DataStore is the interface implemented by plugin implementations
type DataStorePlugin interface {
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

type DataStoreBuiltIn struct {
	plugin DataStorePlugin
}

var _ DataStore = (*DataStoreBuiltIn)(nil)

func NewDataStoreBuiltIn(plugin DataStorePlugin) *DataStoreBuiltIn {
	return &DataStoreBuiltIn{
		plugin: plugin,
	}
}

func (b DataStoreBuiltIn) CreateBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return b.plugin.CreateBundle(ctx, req)
}

func (b DataStoreBuiltIn) UpdateBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return b.plugin.UpdateBundle(ctx, req)
}

func (b DataStoreBuiltIn) AppendBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return b.plugin.AppendBundle(ctx, req)
}

func (b DataStoreBuiltIn) DeleteBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return b.plugin.DeleteBundle(ctx, req)
}

func (b DataStoreBuiltIn) FetchBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return b.plugin.FetchBundle(ctx, req)
}

func (b DataStoreBuiltIn) ListBundles(ctx context.Context, req *common.Empty) (*Bundles, error) {
	return b.plugin.ListBundles(ctx, req)
}

func (b DataStoreBuiltIn) CreateAttestedNodeEntry(ctx context.Context, req *CreateAttestedNodeEntryRequest) (*CreateAttestedNodeEntryResponse, error) {
	return b.plugin.CreateAttestedNodeEntry(ctx, req)
}

func (b DataStoreBuiltIn) FetchAttestedNodeEntry(ctx context.Context, req *FetchAttestedNodeEntryRequest) (*FetchAttestedNodeEntryResponse, error) {
	return b.plugin.FetchAttestedNodeEntry(ctx, req)
}

func (b DataStoreBuiltIn) FetchStaleNodeEntries(ctx context.Context, req *FetchStaleNodeEntriesRequest) (*FetchStaleNodeEntriesResponse, error) {
	return b.plugin.FetchStaleNodeEntries(ctx, req)
}

func (b DataStoreBuiltIn) UpdateAttestedNodeEntry(ctx context.Context, req *UpdateAttestedNodeEntryRequest) (*UpdateAttestedNodeEntryResponse, error) {
	return b.plugin.UpdateAttestedNodeEntry(ctx, req)
}

func (b DataStoreBuiltIn) DeleteAttestedNodeEntry(ctx context.Context, req *DeleteAttestedNodeEntryRequest) (*DeleteAttestedNodeEntryResponse, error) {
	return b.plugin.DeleteAttestedNodeEntry(ctx, req)
}

func (b DataStoreBuiltIn) CreateNodeResolverMapEntry(ctx context.Context, req *CreateNodeResolverMapEntryRequest) (*CreateNodeResolverMapEntryResponse, error) {
	return b.plugin.CreateNodeResolverMapEntry(ctx, req)
}

func (b DataStoreBuiltIn) FetchNodeResolverMapEntry(ctx context.Context, req *FetchNodeResolverMapEntryRequest) (*FetchNodeResolverMapEntryResponse, error) {
	return b.plugin.FetchNodeResolverMapEntry(ctx, req)
}

func (b DataStoreBuiltIn) DeleteNodeResolverMapEntry(ctx context.Context, req *DeleteNodeResolverMapEntryRequest) (*DeleteNodeResolverMapEntryResponse, error) {
	return b.plugin.DeleteNodeResolverMapEntry(ctx, req)
}

func (b DataStoreBuiltIn) RectifyNodeResolverMapEntries(ctx context.Context, req *RectifyNodeResolverMapEntriesRequest) (*RectifyNodeResolverMapEntriesResponse, error) {
	return b.plugin.RectifyNodeResolverMapEntries(ctx, req)
}

func (b DataStoreBuiltIn) CreateRegistrationEntry(ctx context.Context, req *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error) {
	return b.plugin.CreateRegistrationEntry(ctx, req)
}

func (b DataStoreBuiltIn) FetchRegistrationEntry(ctx context.Context, req *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error) {
	return b.plugin.FetchRegistrationEntry(ctx, req)
}

func (b DataStoreBuiltIn) FetchRegistrationEntries(ctx context.Context, req *common.Empty) (*FetchRegistrationEntriesResponse, error) {
	return b.plugin.FetchRegistrationEntries(ctx, req)
}

func (b DataStoreBuiltIn) UpdateRegistrationEntry(ctx context.Context, req *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error) {
	return b.plugin.UpdateRegistrationEntry(ctx, req)
}

func (b DataStoreBuiltIn) DeleteRegistrationEntry(ctx context.Context, req *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error) {
	return b.plugin.DeleteRegistrationEntry(ctx, req)
}

func (b DataStoreBuiltIn) ListParentIDEntries(ctx context.Context, req *ListParentIDEntriesRequest) (*ListParentIDEntriesResponse, error) {
	return b.plugin.ListParentIDEntries(ctx, req)
}

func (b DataStoreBuiltIn) ListSelectorEntries(ctx context.Context, req *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error) {
	return b.plugin.ListSelectorEntries(ctx, req)
}

func (b DataStoreBuiltIn) ListMatchingEntries(ctx context.Context, req *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error) {
	return b.plugin.ListMatchingEntries(ctx, req)
}

func (b DataStoreBuiltIn) ListSpiffeEntries(ctx context.Context, req *ListSpiffeEntriesRequest) (*ListSpiffeEntriesResponse, error) {
	return b.plugin.ListSpiffeEntries(ctx, req)
}

func (b DataStoreBuiltIn) RegisterToken(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	return b.plugin.RegisterToken(ctx, req)
}

func (b DataStoreBuiltIn) FetchToken(ctx context.Context, req *JoinToken) (*JoinToken, error) {
	return b.plugin.FetchToken(ctx, req)
}

func (b DataStoreBuiltIn) DeleteToken(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	return b.plugin.DeleteToken(ctx, req)
}

func (b DataStoreBuiltIn) PruneTokens(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	return b.plugin.PruneTokens(ctx, req)
}

func (b DataStoreBuiltIn) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return b.plugin.Configure(ctx, req)
}

func (b DataStoreBuiltIn) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return b.plugin.GetPluginInfo(ctx, req)
}

var Handshake = go_plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "DataStore",
	MagicCookieValue: "DataStore",
}

type DataStoreGRPCPlugin struct {
	ServerImpl DataStoreServer
}

func (p DataStoreGRPCPlugin) Server(*go_plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p DataStoreGRPCPlugin) Client(b *go_plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p DataStoreGRPCPlugin) GRPCServer(s *grpc.Server) error {
	RegisterDataStoreServer(s, p.ServerImpl)
	return nil
}

func (p DataStoreGRPCPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &DataStoreGRPCClient{client: NewDataStoreClient(c)}, nil
}

type DataStoreGRPCServer struct {
	Plugin DataStorePlugin
}

func (s *DataStoreGRPCServer) CreateBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return s.Plugin.CreateBundle(ctx, req)
}
func (s *DataStoreGRPCServer) UpdateBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return s.Plugin.UpdateBundle(ctx, req)
}
func (s *DataStoreGRPCServer) AppendBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return s.Plugin.AppendBundle(ctx, req)
}
func (s *DataStoreGRPCServer) DeleteBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return s.Plugin.DeleteBundle(ctx, req)
}
func (s *DataStoreGRPCServer) FetchBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return s.Plugin.FetchBundle(ctx, req)
}
func (s *DataStoreGRPCServer) ListBundles(ctx context.Context, req *common.Empty) (*Bundles, error) {
	return s.Plugin.ListBundles(ctx, req)
}
func (s *DataStoreGRPCServer) CreateAttestedNodeEntry(ctx context.Context, req *CreateAttestedNodeEntryRequest) (*CreateAttestedNodeEntryResponse, error) {
	return s.Plugin.CreateAttestedNodeEntry(ctx, req)
}
func (s *DataStoreGRPCServer) FetchAttestedNodeEntry(ctx context.Context, req *FetchAttestedNodeEntryRequest) (*FetchAttestedNodeEntryResponse, error) {
	return s.Plugin.FetchAttestedNodeEntry(ctx, req)
}
func (s *DataStoreGRPCServer) FetchStaleNodeEntries(ctx context.Context, req *FetchStaleNodeEntriesRequest) (*FetchStaleNodeEntriesResponse, error) {
	return s.Plugin.FetchStaleNodeEntries(ctx, req)
}
func (s *DataStoreGRPCServer) UpdateAttestedNodeEntry(ctx context.Context, req *UpdateAttestedNodeEntryRequest) (*UpdateAttestedNodeEntryResponse, error) {
	return s.Plugin.UpdateAttestedNodeEntry(ctx, req)
}
func (s *DataStoreGRPCServer) DeleteAttestedNodeEntry(ctx context.Context, req *DeleteAttestedNodeEntryRequest) (*DeleteAttestedNodeEntryResponse, error) {
	return s.Plugin.DeleteAttestedNodeEntry(ctx, req)
}
func (s *DataStoreGRPCServer) CreateNodeResolverMapEntry(ctx context.Context, req *CreateNodeResolverMapEntryRequest) (*CreateNodeResolverMapEntryResponse, error) {
	return s.Plugin.CreateNodeResolverMapEntry(ctx, req)
}
func (s *DataStoreGRPCServer) FetchNodeResolverMapEntry(ctx context.Context, req *FetchNodeResolverMapEntryRequest) (*FetchNodeResolverMapEntryResponse, error) {
	return s.Plugin.FetchNodeResolverMapEntry(ctx, req)
}
func (s *DataStoreGRPCServer) DeleteNodeResolverMapEntry(ctx context.Context, req *DeleteNodeResolverMapEntryRequest) (*DeleteNodeResolverMapEntryResponse, error) {
	return s.Plugin.DeleteNodeResolverMapEntry(ctx, req)
}
func (s *DataStoreGRPCServer) RectifyNodeResolverMapEntries(ctx context.Context, req *RectifyNodeResolverMapEntriesRequest) (*RectifyNodeResolverMapEntriesResponse, error) {
	return s.Plugin.RectifyNodeResolverMapEntries(ctx, req)
}
func (s *DataStoreGRPCServer) CreateRegistrationEntry(ctx context.Context, req *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error) {
	return s.Plugin.CreateRegistrationEntry(ctx, req)
}
func (s *DataStoreGRPCServer) FetchRegistrationEntry(ctx context.Context, req *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error) {
	return s.Plugin.FetchRegistrationEntry(ctx, req)
}
func (s *DataStoreGRPCServer) FetchRegistrationEntries(ctx context.Context, req *common.Empty) (*FetchRegistrationEntriesResponse, error) {
	return s.Plugin.FetchRegistrationEntries(ctx, req)
}
func (s *DataStoreGRPCServer) UpdateRegistrationEntry(ctx context.Context, req *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error) {
	return s.Plugin.UpdateRegistrationEntry(ctx, req)
}
func (s *DataStoreGRPCServer) DeleteRegistrationEntry(ctx context.Context, req *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error) {
	return s.Plugin.DeleteRegistrationEntry(ctx, req)
}
func (s *DataStoreGRPCServer) ListParentIDEntries(ctx context.Context, req *ListParentIDEntriesRequest) (*ListParentIDEntriesResponse, error) {
	return s.Plugin.ListParentIDEntries(ctx, req)
}
func (s *DataStoreGRPCServer) ListSelectorEntries(ctx context.Context, req *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error) {
	return s.Plugin.ListSelectorEntries(ctx, req)
}
func (s *DataStoreGRPCServer) ListMatchingEntries(ctx context.Context, req *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error) {
	return s.Plugin.ListMatchingEntries(ctx, req)
}
func (s *DataStoreGRPCServer) ListSpiffeEntries(ctx context.Context, req *ListSpiffeEntriesRequest) (*ListSpiffeEntriesResponse, error) {
	return s.Plugin.ListSpiffeEntries(ctx, req)
}
func (s *DataStoreGRPCServer) RegisterToken(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	return s.Plugin.RegisterToken(ctx, req)
}
func (s *DataStoreGRPCServer) FetchToken(ctx context.Context, req *JoinToken) (*JoinToken, error) {
	return s.Plugin.FetchToken(ctx, req)
}
func (s *DataStoreGRPCServer) DeleteToken(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	return s.Plugin.DeleteToken(ctx, req)
}
func (s *DataStoreGRPCServer) PruneTokens(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	return s.Plugin.PruneTokens(ctx, req)
}
func (s *DataStoreGRPCServer) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return s.Plugin.Configure(ctx, req)
}
func (s *DataStoreGRPCServer) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return s.Plugin.GetPluginInfo(ctx, req)
}

type DataStoreGRPCClient struct {
	client DataStoreClient
}

func (c *DataStoreGRPCClient) CreateBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return c.client.CreateBundle(ctx, req)
}
func (c *DataStoreGRPCClient) UpdateBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return c.client.UpdateBundle(ctx, req)
}
func (c *DataStoreGRPCClient) AppendBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return c.client.AppendBundle(ctx, req)
}
func (c *DataStoreGRPCClient) DeleteBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return c.client.DeleteBundle(ctx, req)
}
func (c *DataStoreGRPCClient) FetchBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	return c.client.FetchBundle(ctx, req)
}
func (c *DataStoreGRPCClient) ListBundles(ctx context.Context, req *common.Empty) (*Bundles, error) {
	return c.client.ListBundles(ctx, req)
}
func (c *DataStoreGRPCClient) CreateAttestedNodeEntry(ctx context.Context, req *CreateAttestedNodeEntryRequest) (*CreateAttestedNodeEntryResponse, error) {
	return c.client.CreateAttestedNodeEntry(ctx, req)
}
func (c *DataStoreGRPCClient) FetchAttestedNodeEntry(ctx context.Context, req *FetchAttestedNodeEntryRequest) (*FetchAttestedNodeEntryResponse, error) {
	return c.client.FetchAttestedNodeEntry(ctx, req)
}
func (c *DataStoreGRPCClient) FetchStaleNodeEntries(ctx context.Context, req *FetchStaleNodeEntriesRequest) (*FetchStaleNodeEntriesResponse, error) {
	return c.client.FetchStaleNodeEntries(ctx, req)
}
func (c *DataStoreGRPCClient) UpdateAttestedNodeEntry(ctx context.Context, req *UpdateAttestedNodeEntryRequest) (*UpdateAttestedNodeEntryResponse, error) {
	return c.client.UpdateAttestedNodeEntry(ctx, req)
}
func (c *DataStoreGRPCClient) DeleteAttestedNodeEntry(ctx context.Context, req *DeleteAttestedNodeEntryRequest) (*DeleteAttestedNodeEntryResponse, error) {
	return c.client.DeleteAttestedNodeEntry(ctx, req)
}
func (c *DataStoreGRPCClient) CreateNodeResolverMapEntry(ctx context.Context, req *CreateNodeResolverMapEntryRequest) (*CreateNodeResolverMapEntryResponse, error) {
	return c.client.CreateNodeResolverMapEntry(ctx, req)
}
func (c *DataStoreGRPCClient) FetchNodeResolverMapEntry(ctx context.Context, req *FetchNodeResolverMapEntryRequest) (*FetchNodeResolverMapEntryResponse, error) {
	return c.client.FetchNodeResolverMapEntry(ctx, req)
}
func (c *DataStoreGRPCClient) DeleteNodeResolverMapEntry(ctx context.Context, req *DeleteNodeResolverMapEntryRequest) (*DeleteNodeResolverMapEntryResponse, error) {
	return c.client.DeleteNodeResolverMapEntry(ctx, req)
}
func (c *DataStoreGRPCClient) RectifyNodeResolverMapEntries(ctx context.Context, req *RectifyNodeResolverMapEntriesRequest) (*RectifyNodeResolverMapEntriesResponse, error) {
	return c.client.RectifyNodeResolverMapEntries(ctx, req)
}
func (c *DataStoreGRPCClient) CreateRegistrationEntry(ctx context.Context, req *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error) {
	return c.client.CreateRegistrationEntry(ctx, req)
}
func (c *DataStoreGRPCClient) FetchRegistrationEntry(ctx context.Context, req *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error) {
	return c.client.FetchRegistrationEntry(ctx, req)
}
func (c *DataStoreGRPCClient) FetchRegistrationEntries(ctx context.Context, req *common.Empty) (*FetchRegistrationEntriesResponse, error) {
	return c.client.FetchRegistrationEntries(ctx, req)
}
func (c *DataStoreGRPCClient) UpdateRegistrationEntry(ctx context.Context, req *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error) {
	return c.client.UpdateRegistrationEntry(ctx, req)
}
func (c *DataStoreGRPCClient) DeleteRegistrationEntry(ctx context.Context, req *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error) {
	return c.client.DeleteRegistrationEntry(ctx, req)
}
func (c *DataStoreGRPCClient) ListParentIDEntries(ctx context.Context, req *ListParentIDEntriesRequest) (*ListParentIDEntriesResponse, error) {
	return c.client.ListParentIDEntries(ctx, req)
}
func (c *DataStoreGRPCClient) ListSelectorEntries(ctx context.Context, req *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error) {
	return c.client.ListSelectorEntries(ctx, req)
}
func (c *DataStoreGRPCClient) ListMatchingEntries(ctx context.Context, req *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error) {
	return c.client.ListMatchingEntries(ctx, req)
}
func (c *DataStoreGRPCClient) ListSpiffeEntries(ctx context.Context, req *ListSpiffeEntriesRequest) (*ListSpiffeEntriesResponse, error) {
	return c.client.ListSpiffeEntries(ctx, req)
}
func (c *DataStoreGRPCClient) RegisterToken(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	return c.client.RegisterToken(ctx, req)
}
func (c *DataStoreGRPCClient) FetchToken(ctx context.Context, req *JoinToken) (*JoinToken, error) {
	return c.client.FetchToken(ctx, req)
}
func (c *DataStoreGRPCClient) DeleteToken(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	return c.client.DeleteToken(ctx, req)
}
func (c *DataStoreGRPCClient) PruneTokens(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	return c.client.PruneTokens(ctx, req)
}
func (c *DataStoreGRPCClient) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return c.client.Configure(ctx, req)
}
func (c *DataStoreGRPCClient) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return c.client.GetPluginInfo(ctx, req)
}
