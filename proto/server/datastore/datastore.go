package datastore

import (
	"context"
	"net/rpc"

	"github.com/golang/protobuf/ptypes/empty"
	go_plugin "github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/proto/common/plugin"
	"google.golang.org/grpc"
)

// DataStore is the interface used by all non-catalog components.
type DataStore interface {
	CreateBundle(context.Context, *CreateBundleRequest) (*CreateBundleResponse, error)
	FetchBundle(context.Context, *FetchBundleRequest) (*FetchBundleResponse, error)
	ListBundles(context.Context, *ListBundlesRequest) (*ListBundlesResponse, error)
	UpdateBundle(context.Context, *UpdateBundleRequest) (*UpdateBundleResponse, error)
	AppendBundle(context.Context, *AppendBundleRequest) (*AppendBundleResponse, error)
	DeleteBundle(context.Context, *DeleteBundleRequest) (*DeleteBundleResponse, error)
	CreateAttestedNode(context.Context, *CreateAttestedNodeRequest) (*CreateAttestedNodeResponse, error)
	FetchAttestedNode(context.Context, *FetchAttestedNodeRequest) (*FetchAttestedNodeResponse, error)
	ListAttestedNodes(context.Context, *ListAttestedNodesRequest) (*ListAttestedNodesResponse, error)
	UpdateAttestedNode(context.Context, *UpdateAttestedNodeRequest) (*UpdateAttestedNodeResponse, error)
	DeleteAttestedNode(context.Context, *DeleteAttestedNodeRequest) (*DeleteAttestedNodeResponse, error)
	SetNodeSelectors(context.Context, *SetNodeSelectorsRequest) (*SetNodeSelectorsResponse, error)
	GetNodeSelectors(context.Context, *GetNodeSelectorsRequest) (*GetNodeSelectorsResponse, error)
	CreateRegistrationEntry(context.Context, *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error)
	FetchRegistrationEntry(context.Context, *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error)
	ListRegistrationEntries(context.Context, *ListRegistrationEntriesRequest) (*ListRegistrationEntriesResponse, error)
	UpdateRegistrationEntry(context.Context, *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error)
	DeleteRegistrationEntry(context.Context, *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error)
	CreateJoinToken(context.Context, *CreateJoinTokenRequest) (*CreateJoinTokenResponse, error)
	FetchJoinToken(context.Context, *FetchJoinTokenRequest) (*FetchJoinTokenResponse, error)
	DeleteJoinToken(context.Context, *DeleteJoinTokenRequest) (*DeleteJoinTokenResponse, error)
	PruneJoinTokens(context.Context, *PruneJoinTokensRequest) (*PruneJoinTokensResponse, error)
}

// Plugin is the interface implemented by plugin implementations
type Plugin interface {
	CreateBundle(context.Context, *CreateBundleRequest) (*CreateBundleResponse, error)
	FetchBundle(context.Context, *FetchBundleRequest) (*FetchBundleResponse, error)
	ListBundles(context.Context, *ListBundlesRequest) (*ListBundlesResponse, error)
	UpdateBundle(context.Context, *UpdateBundleRequest) (*UpdateBundleResponse, error)
	AppendBundle(context.Context, *AppendBundleRequest) (*AppendBundleResponse, error)
	DeleteBundle(context.Context, *DeleteBundleRequest) (*DeleteBundleResponse, error)
	CreateAttestedNode(context.Context, *CreateAttestedNodeRequest) (*CreateAttestedNodeResponse, error)
	FetchAttestedNode(context.Context, *FetchAttestedNodeRequest) (*FetchAttestedNodeResponse, error)
	ListAttestedNodes(context.Context, *ListAttestedNodesRequest) (*ListAttestedNodesResponse, error)
	UpdateAttestedNode(context.Context, *UpdateAttestedNodeRequest) (*UpdateAttestedNodeResponse, error)
	DeleteAttestedNode(context.Context, *DeleteAttestedNodeRequest) (*DeleteAttestedNodeResponse, error)
	SetNodeSelectors(context.Context, *SetNodeSelectorsRequest) (*SetNodeSelectorsResponse, error)
	GetNodeSelectors(context.Context, *GetNodeSelectorsRequest) (*GetNodeSelectorsResponse, error)
	CreateRegistrationEntry(context.Context, *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error)
	FetchRegistrationEntry(context.Context, *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error)
	ListRegistrationEntries(context.Context, *ListRegistrationEntriesRequest) (*ListRegistrationEntriesResponse, error)
	UpdateRegistrationEntry(context.Context, *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error)
	DeleteRegistrationEntry(context.Context, *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error)
	CreateJoinToken(context.Context, *CreateJoinTokenRequest) (*CreateJoinTokenResponse, error)
	FetchJoinToken(context.Context, *FetchJoinTokenRequest) (*FetchJoinTokenResponse, error)
	DeleteJoinToken(context.Context, *DeleteJoinTokenRequest) (*DeleteJoinTokenResponse, error)
	PruneJoinTokens(context.Context, *PruneJoinTokensRequest) (*PruneJoinTokensResponse, error)
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

func (b BuiltIn) CreateBundle(ctx context.Context, req *CreateBundleRequest) (*CreateBundleResponse, error) {
	resp, err := b.plugin.CreateBundle(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) FetchBundle(ctx context.Context, req *FetchBundleRequest) (*FetchBundleResponse, error) {
	resp, err := b.plugin.FetchBundle(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) ListBundles(ctx context.Context, req *ListBundlesRequest) (*ListBundlesResponse, error) {
	resp, err := b.plugin.ListBundles(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) UpdateBundle(ctx context.Context, req *UpdateBundleRequest) (*UpdateBundleResponse, error) {
	resp, err := b.plugin.UpdateBundle(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) AppendBundle(ctx context.Context, req *AppendBundleRequest) (*AppendBundleResponse, error) {
	resp, err := b.plugin.AppendBundle(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) DeleteBundle(ctx context.Context, req *DeleteBundleRequest) (*DeleteBundleResponse, error) {
	resp, err := b.plugin.DeleteBundle(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) CreateAttestedNode(ctx context.Context, req *CreateAttestedNodeRequest) (*CreateAttestedNodeResponse, error) {
	resp, err := b.plugin.CreateAttestedNode(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) FetchAttestedNode(ctx context.Context, req *FetchAttestedNodeRequest) (*FetchAttestedNodeResponse, error) {
	resp, err := b.plugin.FetchAttestedNode(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) ListAttestedNodes(ctx context.Context, req *ListAttestedNodesRequest) (*ListAttestedNodesResponse, error) {
	resp, err := b.plugin.ListAttestedNodes(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) UpdateAttestedNode(ctx context.Context, req *UpdateAttestedNodeRequest) (*UpdateAttestedNodeResponse, error) {
	resp, err := b.plugin.UpdateAttestedNode(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) DeleteAttestedNode(ctx context.Context, req *DeleteAttestedNodeRequest) (*DeleteAttestedNodeResponse, error) {
	resp, err := b.plugin.DeleteAttestedNode(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) SetNodeSelectors(ctx context.Context, req *SetNodeSelectorsRequest) (*SetNodeSelectorsResponse, error) {
	resp, err := b.plugin.SetNodeSelectors(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) GetNodeSelectors(ctx context.Context, req *GetNodeSelectorsRequest) (*GetNodeSelectorsResponse, error) {
	resp, err := b.plugin.GetNodeSelectors(ctx, req)
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

func (b BuiltIn) ListRegistrationEntries(ctx context.Context, req *ListRegistrationEntriesRequest) (*ListRegistrationEntriesResponse, error) {
	resp, err := b.plugin.ListRegistrationEntries(ctx, req)
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

func (b BuiltIn) CreateJoinToken(ctx context.Context, req *CreateJoinTokenRequest) (*CreateJoinTokenResponse, error) {
	resp, err := b.plugin.CreateJoinToken(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) FetchJoinToken(ctx context.Context, req *FetchJoinTokenRequest) (*FetchJoinTokenResponse, error) {
	resp, err := b.plugin.FetchJoinToken(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) DeleteJoinToken(ctx context.Context, req *DeleteJoinTokenRequest) (*DeleteJoinTokenResponse, error) {
	resp, err := b.plugin.DeleteJoinToken(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) PruneJoinTokens(ctx context.Context, req *PruneJoinTokensRequest) (*PruneJoinTokensResponse, error) {
	resp, err := b.plugin.PruneJoinTokens(ctx, req)
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

func (s *GRPCServer) CreateBundle(ctx context.Context, req *CreateBundleRequest) (*CreateBundleResponse, error) {
	return s.Plugin.CreateBundle(ctx, req)
}
func (s *GRPCServer) FetchBundle(ctx context.Context, req *FetchBundleRequest) (*FetchBundleResponse, error) {
	return s.Plugin.FetchBundle(ctx, req)
}
func (s *GRPCServer) ListBundles(ctx context.Context, req *ListBundlesRequest) (*ListBundlesResponse, error) {
	return s.Plugin.ListBundles(ctx, req)
}
func (s *GRPCServer) UpdateBundle(ctx context.Context, req *UpdateBundleRequest) (*UpdateBundleResponse, error) {
	return s.Plugin.UpdateBundle(ctx, req)
}
func (s *GRPCServer) AppendBundle(ctx context.Context, req *AppendBundleRequest) (*AppendBundleResponse, error) {
	return s.Plugin.AppendBundle(ctx, req)
}
func (s *GRPCServer) DeleteBundle(ctx context.Context, req *DeleteBundleRequest) (*DeleteBundleResponse, error) {
	return s.Plugin.DeleteBundle(ctx, req)
}
func (s *GRPCServer) CreateAttestedNode(ctx context.Context, req *CreateAttestedNodeRequest) (*CreateAttestedNodeResponse, error) {
	return s.Plugin.CreateAttestedNode(ctx, req)
}
func (s *GRPCServer) FetchAttestedNode(ctx context.Context, req *FetchAttestedNodeRequest) (*FetchAttestedNodeResponse, error) {
	return s.Plugin.FetchAttestedNode(ctx, req)
}
func (s *GRPCServer) ListAttestedNodes(ctx context.Context, req *ListAttestedNodesRequest) (*ListAttestedNodesResponse, error) {
	return s.Plugin.ListAttestedNodes(ctx, req)
}
func (s *GRPCServer) UpdateAttestedNode(ctx context.Context, req *UpdateAttestedNodeRequest) (*UpdateAttestedNodeResponse, error) {
	return s.Plugin.UpdateAttestedNode(ctx, req)
}
func (s *GRPCServer) DeleteAttestedNode(ctx context.Context, req *DeleteAttestedNodeRequest) (*DeleteAttestedNodeResponse, error) {
	return s.Plugin.DeleteAttestedNode(ctx, req)
}
func (s *GRPCServer) SetNodeSelectors(ctx context.Context, req *SetNodeSelectorsRequest) (*SetNodeSelectorsResponse, error) {
	return s.Plugin.SetNodeSelectors(ctx, req)
}
func (s *GRPCServer) GetNodeSelectors(ctx context.Context, req *GetNodeSelectorsRequest) (*GetNodeSelectorsResponse, error) {
	return s.Plugin.GetNodeSelectors(ctx, req)
}
func (s *GRPCServer) CreateRegistrationEntry(ctx context.Context, req *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error) {
	return s.Plugin.CreateRegistrationEntry(ctx, req)
}
func (s *GRPCServer) FetchRegistrationEntry(ctx context.Context, req *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error) {
	return s.Plugin.FetchRegistrationEntry(ctx, req)
}
func (s *GRPCServer) ListRegistrationEntries(ctx context.Context, req *ListRegistrationEntriesRequest) (*ListRegistrationEntriesResponse, error) {
	return s.Plugin.ListRegistrationEntries(ctx, req)
}
func (s *GRPCServer) UpdateRegistrationEntry(ctx context.Context, req *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error) {
	return s.Plugin.UpdateRegistrationEntry(ctx, req)
}
func (s *GRPCServer) DeleteRegistrationEntry(ctx context.Context, req *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error) {
	return s.Plugin.DeleteRegistrationEntry(ctx, req)
}
func (s *GRPCServer) CreateJoinToken(ctx context.Context, req *CreateJoinTokenRequest) (*CreateJoinTokenResponse, error) {
	return s.Plugin.CreateJoinToken(ctx, req)
}
func (s *GRPCServer) FetchJoinToken(ctx context.Context, req *FetchJoinTokenRequest) (*FetchJoinTokenResponse, error) {
	return s.Plugin.FetchJoinToken(ctx, req)
}
func (s *GRPCServer) DeleteJoinToken(ctx context.Context, req *DeleteJoinTokenRequest) (*DeleteJoinTokenResponse, error) {
	return s.Plugin.DeleteJoinToken(ctx, req)
}
func (s *GRPCServer) PruneJoinTokens(ctx context.Context, req *PruneJoinTokensRequest) (*PruneJoinTokensResponse, error) {
	return s.Plugin.PruneJoinTokens(ctx, req)
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

func (c *GRPCClient) CreateBundle(ctx context.Context, req *CreateBundleRequest) (*CreateBundleResponse, error) {
	return c.client.CreateBundle(ctx, req)
}
func (c *GRPCClient) FetchBundle(ctx context.Context, req *FetchBundleRequest) (*FetchBundleResponse, error) {
	return c.client.FetchBundle(ctx, req)
}
func (c *GRPCClient) ListBundles(ctx context.Context, req *ListBundlesRequest) (*ListBundlesResponse, error) {
	return c.client.ListBundles(ctx, req)
}
func (c *GRPCClient) UpdateBundle(ctx context.Context, req *UpdateBundleRequest) (*UpdateBundleResponse, error) {
	return c.client.UpdateBundle(ctx, req)
}
func (c *GRPCClient) AppendBundle(ctx context.Context, req *AppendBundleRequest) (*AppendBundleResponse, error) {
	return c.client.AppendBundle(ctx, req)
}
func (c *GRPCClient) DeleteBundle(ctx context.Context, req *DeleteBundleRequest) (*DeleteBundleResponse, error) {
	return c.client.DeleteBundle(ctx, req)
}
func (c *GRPCClient) CreateAttestedNode(ctx context.Context, req *CreateAttestedNodeRequest) (*CreateAttestedNodeResponse, error) {
	return c.client.CreateAttestedNode(ctx, req)
}
func (c *GRPCClient) FetchAttestedNode(ctx context.Context, req *FetchAttestedNodeRequest) (*FetchAttestedNodeResponse, error) {
	return c.client.FetchAttestedNode(ctx, req)
}
func (c *GRPCClient) ListAttestedNodes(ctx context.Context, req *ListAttestedNodesRequest) (*ListAttestedNodesResponse, error) {
	return c.client.ListAttestedNodes(ctx, req)
}
func (c *GRPCClient) UpdateAttestedNode(ctx context.Context, req *UpdateAttestedNodeRequest) (*UpdateAttestedNodeResponse, error) {
	return c.client.UpdateAttestedNode(ctx, req)
}
func (c *GRPCClient) DeleteAttestedNode(ctx context.Context, req *DeleteAttestedNodeRequest) (*DeleteAttestedNodeResponse, error) {
	return c.client.DeleteAttestedNode(ctx, req)
}
func (c *GRPCClient) SetNodeSelectors(ctx context.Context, req *SetNodeSelectorsRequest) (*SetNodeSelectorsResponse, error) {
	return c.client.SetNodeSelectors(ctx, req)
}
func (c *GRPCClient) GetNodeSelectors(ctx context.Context, req *GetNodeSelectorsRequest) (*GetNodeSelectorsResponse, error) {
	return c.client.GetNodeSelectors(ctx, req)
}
func (c *GRPCClient) CreateRegistrationEntry(ctx context.Context, req *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error) {
	return c.client.CreateRegistrationEntry(ctx, req)
}
func (c *GRPCClient) FetchRegistrationEntry(ctx context.Context, req *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error) {
	return c.client.FetchRegistrationEntry(ctx, req)
}
func (c *GRPCClient) ListRegistrationEntries(ctx context.Context, req *ListRegistrationEntriesRequest) (*ListRegistrationEntriesResponse, error) {
	return c.client.ListRegistrationEntries(ctx, req)
}
func (c *GRPCClient) UpdateRegistrationEntry(ctx context.Context, req *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error) {
	return c.client.UpdateRegistrationEntry(ctx, req)
}
func (c *GRPCClient) DeleteRegistrationEntry(ctx context.Context, req *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error) {
	return c.client.DeleteRegistrationEntry(ctx, req)
}
func (c *GRPCClient) CreateJoinToken(ctx context.Context, req *CreateJoinTokenRequest) (*CreateJoinTokenResponse, error) {
	return c.client.CreateJoinToken(ctx, req)
}
func (c *GRPCClient) FetchJoinToken(ctx context.Context, req *FetchJoinTokenRequest) (*FetchJoinTokenResponse, error) {
	return c.client.FetchJoinToken(ctx, req)
}
func (c *GRPCClient) DeleteJoinToken(ctx context.Context, req *DeleteJoinTokenRequest) (*DeleteJoinTokenResponse, error) {
	return c.client.DeleteJoinToken(ctx, req)
}
func (c *GRPCClient) PruneJoinTokens(ctx context.Context, req *PruneJoinTokensRequest) (*PruneJoinTokensResponse, error) {
	return c.client.PruneJoinTokens(ctx, req)
}
func (c *GRPCClient) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return c.client.Configure(ctx, req)
}
func (c *GRPCClient) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return c.client.GetPluginInfo(ctx, req)
}
