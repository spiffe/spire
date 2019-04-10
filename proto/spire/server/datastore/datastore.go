// Provides interfaces and adapters for the DataStore service
//
// Generated code. Do not modify by hand.
package datastore

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc"
)

const (
	Type = "DataStore"
)

// DataStore is the client interface for the service type DataStore interface.
type DataStore interface {
	AppendBundle(context.Context, *AppendBundleRequest) (*AppendBundleResponse, error)
	CreateAttestedNode(context.Context, *CreateAttestedNodeRequest) (*CreateAttestedNodeResponse, error)
	CreateBundle(context.Context, *CreateBundleRequest) (*CreateBundleResponse, error)
	CreateJoinToken(context.Context, *CreateJoinTokenRequest) (*CreateJoinTokenResponse, error)
	CreateRegistrationEntry(context.Context, *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error)
	DeleteAttestedNode(context.Context, *DeleteAttestedNodeRequest) (*DeleteAttestedNodeResponse, error)
	DeleteBundle(context.Context, *DeleteBundleRequest) (*DeleteBundleResponse, error)
	DeleteJoinToken(context.Context, *DeleteJoinTokenRequest) (*DeleteJoinTokenResponse, error)
	DeleteRegistrationEntry(context.Context, *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error)
	FetchAttestedNode(context.Context, *FetchAttestedNodeRequest) (*FetchAttestedNodeResponse, error)
	FetchBundle(context.Context, *FetchBundleRequest) (*FetchBundleResponse, error)
	FetchJoinToken(context.Context, *FetchJoinTokenRequest) (*FetchJoinTokenResponse, error)
	FetchRegistrationEntry(context.Context, *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error)
	GetNodeSelectors(context.Context, *GetNodeSelectorsRequest) (*GetNodeSelectorsResponse, error)
	ListAttestedNodes(context.Context, *ListAttestedNodesRequest) (*ListAttestedNodesResponse, error)
	ListBundles(context.Context, *ListBundlesRequest) (*ListBundlesResponse, error)
	ListRegistrationEntries(context.Context, *ListRegistrationEntriesRequest) (*ListRegistrationEntriesResponse, error)
	PruneJoinTokens(context.Context, *PruneJoinTokensRequest) (*PruneJoinTokensResponse, error)
	PruneRegistrationEntries(context.Context, *PruneRegistrationEntriesRequest) (*PruneRegistrationEntriesResponse, error)
	SetNodeSelectors(context.Context, *SetNodeSelectorsRequest) (*SetNodeSelectorsResponse, error)
	UpdateAttestedNode(context.Context, *UpdateAttestedNodeRequest) (*UpdateAttestedNodeResponse, error)
	UpdateBundle(context.Context, *UpdateBundleRequest) (*UpdateBundleResponse, error)
	UpdateRegistrationEntry(context.Context, *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error)
}

// Plugin is the client interface for the service with the plugin related methods used by the catalog to initialize the plugin.
type Plugin interface {
	AppendBundle(context.Context, *AppendBundleRequest) (*AppendBundleResponse, error)
	Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
	CreateAttestedNode(context.Context, *CreateAttestedNodeRequest) (*CreateAttestedNodeResponse, error)
	CreateBundle(context.Context, *CreateBundleRequest) (*CreateBundleResponse, error)
	CreateJoinToken(context.Context, *CreateJoinTokenRequest) (*CreateJoinTokenResponse, error)
	CreateRegistrationEntry(context.Context, *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error)
	DeleteAttestedNode(context.Context, *DeleteAttestedNodeRequest) (*DeleteAttestedNodeResponse, error)
	DeleteBundle(context.Context, *DeleteBundleRequest) (*DeleteBundleResponse, error)
	DeleteJoinToken(context.Context, *DeleteJoinTokenRequest) (*DeleteJoinTokenResponse, error)
	DeleteRegistrationEntry(context.Context, *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error)
	FetchAttestedNode(context.Context, *FetchAttestedNodeRequest) (*FetchAttestedNodeResponse, error)
	FetchBundle(context.Context, *FetchBundleRequest) (*FetchBundleResponse, error)
	FetchJoinToken(context.Context, *FetchJoinTokenRequest) (*FetchJoinTokenResponse, error)
	FetchRegistrationEntry(context.Context, *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error)
	GetNodeSelectors(context.Context, *GetNodeSelectorsRequest) (*GetNodeSelectorsResponse, error)
	GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error)
	ListAttestedNodes(context.Context, *ListAttestedNodesRequest) (*ListAttestedNodesResponse, error)
	ListBundles(context.Context, *ListBundlesRequest) (*ListBundlesResponse, error)
	ListRegistrationEntries(context.Context, *ListRegistrationEntriesRequest) (*ListRegistrationEntriesResponse, error)
	PruneJoinTokens(context.Context, *PruneJoinTokensRequest) (*PruneJoinTokensResponse, error)
	PruneRegistrationEntries(context.Context, *PruneRegistrationEntriesRequest) (*PruneRegistrationEntriesResponse, error)
	SetNodeSelectors(context.Context, *SetNodeSelectorsRequest) (*SetNodeSelectorsResponse, error)
	UpdateAttestedNode(context.Context, *UpdateAttestedNodeRequest) (*UpdateAttestedNodeResponse, error)
	UpdateBundle(context.Context, *UpdateBundleRequest) (*UpdateBundleResponse, error)
	UpdateRegistrationEntry(context.Context, *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error)
}

// PluginServer returns a catalog PluginServer implementation for the DataStore plugin.
func PluginServer(server DataStoreServer) catalog.PluginServer {
	return &pluginServer{
		server: server,
	}
}

type pluginServer struct {
	server DataStoreServer
}

func (s pluginServer) PluginType() string {
	return Type
}

func (s pluginServer) PluginClient() catalog.PluginClient {
	return PluginClient
}

func (s pluginServer) RegisterPluginServer(server *grpc.Server) interface{} {
	RegisterDataStoreServer(server, s.server)
	return s.server
}

// PluginClient is a catalog PluginClient implementation for the DataStore plugin.
var PluginClient catalog.PluginClient = pluginClient{}

type pluginClient struct{}

func (pluginClient) PluginType() string {
	return Type
}

func (pluginClient) NewPluginClient(conn *grpc.ClientConn) interface{} {
	return AdaptPluginClient(NewDataStoreClient(conn))
}

func AdaptPluginClient(client DataStoreClient) DataStore {
	return pluginClientAdapter{client: client}
}

type pluginClientAdapter struct {
	client DataStoreClient
}

func (a pluginClientAdapter) AppendBundle(ctx context.Context, in *AppendBundleRequest) (*AppendBundleResponse, error) {
	return a.client.AppendBundle(ctx, in)
}

func (a pluginClientAdapter) Configure(ctx context.Context, in *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return a.client.Configure(ctx, in)
}

func (a pluginClientAdapter) CreateAttestedNode(ctx context.Context, in *CreateAttestedNodeRequest) (*CreateAttestedNodeResponse, error) {
	return a.client.CreateAttestedNode(ctx, in)
}

func (a pluginClientAdapter) CreateBundle(ctx context.Context, in *CreateBundleRequest) (*CreateBundleResponse, error) {
	return a.client.CreateBundle(ctx, in)
}

func (a pluginClientAdapter) CreateJoinToken(ctx context.Context, in *CreateJoinTokenRequest) (*CreateJoinTokenResponse, error) {
	return a.client.CreateJoinToken(ctx, in)
}

func (a pluginClientAdapter) CreateRegistrationEntry(ctx context.Context, in *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error) {
	return a.client.CreateRegistrationEntry(ctx, in)
}

func (a pluginClientAdapter) DeleteAttestedNode(ctx context.Context, in *DeleteAttestedNodeRequest) (*DeleteAttestedNodeResponse, error) {
	return a.client.DeleteAttestedNode(ctx, in)
}

func (a pluginClientAdapter) DeleteBundle(ctx context.Context, in *DeleteBundleRequest) (*DeleteBundleResponse, error) {
	return a.client.DeleteBundle(ctx, in)
}

func (a pluginClientAdapter) DeleteJoinToken(ctx context.Context, in *DeleteJoinTokenRequest) (*DeleteJoinTokenResponse, error) {
	return a.client.DeleteJoinToken(ctx, in)
}

func (a pluginClientAdapter) DeleteRegistrationEntry(ctx context.Context, in *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error) {
	return a.client.DeleteRegistrationEntry(ctx, in)
}

func (a pluginClientAdapter) FetchAttestedNode(ctx context.Context, in *FetchAttestedNodeRequest) (*FetchAttestedNodeResponse, error) {
	return a.client.FetchAttestedNode(ctx, in)
}

func (a pluginClientAdapter) FetchBundle(ctx context.Context, in *FetchBundleRequest) (*FetchBundleResponse, error) {
	return a.client.FetchBundle(ctx, in)
}

func (a pluginClientAdapter) FetchJoinToken(ctx context.Context, in *FetchJoinTokenRequest) (*FetchJoinTokenResponse, error) {
	return a.client.FetchJoinToken(ctx, in)
}

func (a pluginClientAdapter) FetchRegistrationEntry(ctx context.Context, in *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error) {
	return a.client.FetchRegistrationEntry(ctx, in)
}

func (a pluginClientAdapter) GetNodeSelectors(ctx context.Context, in *GetNodeSelectorsRequest) (*GetNodeSelectorsResponse, error) {
	return a.client.GetNodeSelectors(ctx, in)
}

func (a pluginClientAdapter) GetPluginInfo(ctx context.Context, in *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return a.client.GetPluginInfo(ctx, in)
}

func (a pluginClientAdapter) ListAttestedNodes(ctx context.Context, in *ListAttestedNodesRequest) (*ListAttestedNodesResponse, error) {
	return a.client.ListAttestedNodes(ctx, in)
}

func (a pluginClientAdapter) ListBundles(ctx context.Context, in *ListBundlesRequest) (*ListBundlesResponse, error) {
	return a.client.ListBundles(ctx, in)
}

func (a pluginClientAdapter) ListRegistrationEntries(ctx context.Context, in *ListRegistrationEntriesRequest) (*ListRegistrationEntriesResponse, error) {
	return a.client.ListRegistrationEntries(ctx, in)
}

func (a pluginClientAdapter) PruneJoinTokens(ctx context.Context, in *PruneJoinTokensRequest) (*PruneJoinTokensResponse, error) {
	return a.client.PruneJoinTokens(ctx, in)
}

func (a pluginClientAdapter) PruneRegistrationEntries(ctx context.Context, in *PruneRegistrationEntriesRequest) (*PruneRegistrationEntriesResponse, error) {
	return a.client.PruneRegistrationEntries(ctx, in)
}

func (a pluginClientAdapter) SetNodeSelectors(ctx context.Context, in *SetNodeSelectorsRequest) (*SetNodeSelectorsResponse, error) {
	return a.client.SetNodeSelectors(ctx, in)
}

func (a pluginClientAdapter) UpdateAttestedNode(ctx context.Context, in *UpdateAttestedNodeRequest) (*UpdateAttestedNodeResponse, error) {
	return a.client.UpdateAttestedNode(ctx, in)
}

func (a pluginClientAdapter) UpdateBundle(ctx context.Context, in *UpdateBundleRequest) (*UpdateBundleResponse, error) {
	return a.client.UpdateBundle(ctx, in)
}

func (a pluginClientAdapter) UpdateRegistrationEntry(ctx context.Context, in *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error) {
	return a.client.UpdateRegistrationEntry(ctx, in)
}
