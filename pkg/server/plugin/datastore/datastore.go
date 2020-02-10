// Provides interfaces and adapters for the DataStore service
//
// Generated code. Do not modify by hand.
package datastore

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/datastore"
	"google.golang.org/grpc"
)

type AppendBundleRequest = datastore.AppendBundleRequest                           //nolint: golint
type AppendBundleResponse = datastore.AppendBundleResponse                         //nolint: golint
type BySelectors = datastore.BySelectors                                           //nolint: golint
type BySelectors_MatchBehavior = datastore.BySelectors_MatchBehavior               //nolint: golint
type CreateAttestedNodeRequest = datastore.CreateAttestedNodeRequest               //nolint: golint
type CreateAttestedNodeResponse = datastore.CreateAttestedNodeResponse             //nolint: golint
type CreateBundleRequest = datastore.CreateBundleRequest                           //nolint: golint
type CreateBundleResponse = datastore.CreateBundleResponse                         //nolint: golint
type CreateJoinTokenRequest = datastore.CreateJoinTokenRequest                     //nolint: golint
type CreateJoinTokenResponse = datastore.CreateJoinTokenResponse                   //nolint: golint
type CreateRegistrationEntryRequest = datastore.CreateRegistrationEntryRequest     //nolint: golint
type CreateRegistrationEntryResponse = datastore.CreateRegistrationEntryResponse   //nolint: golint
type DataStoreClient = datastore.DataStoreClient                                   //nolint: golint
type DataStoreServer = datastore.DataStoreServer                                   //nolint: golint
type DeleteAttestedNodeRequest = datastore.DeleteAttestedNodeRequest               //nolint: golint
type DeleteAttestedNodeResponse = datastore.DeleteAttestedNodeResponse             //nolint: golint
type DeleteBundleRequest = datastore.DeleteBundleRequest                           //nolint: golint
type DeleteBundleRequest_Mode = datastore.DeleteBundleRequest_Mode                 //nolint: golint
type DeleteBundleResponse = datastore.DeleteBundleResponse                         //nolint: golint
type DeleteJoinTokenRequest = datastore.DeleteJoinTokenRequest                     //nolint: golint
type DeleteJoinTokenResponse = datastore.DeleteJoinTokenResponse                   //nolint: golint
type DeleteRegistrationEntryRequest = datastore.DeleteRegistrationEntryRequest     //nolint: golint
type DeleteRegistrationEntryResponse = datastore.DeleteRegistrationEntryResponse   //nolint: golint
type FetchAttestedNodeRequest = datastore.FetchAttestedNodeRequest                 //nolint: golint
type FetchAttestedNodeResponse = datastore.FetchAttestedNodeResponse               //nolint: golint
type FetchBundleRequest = datastore.FetchBundleRequest                             //nolint: golint
type FetchBundleResponse = datastore.FetchBundleResponse                           //nolint: golint
type FetchJoinTokenRequest = datastore.FetchJoinTokenRequest                       //nolint: golint
type FetchJoinTokenResponse = datastore.FetchJoinTokenResponse                     //nolint: golint
type FetchRegistrationEntryRequest = datastore.FetchRegistrationEntryRequest       //nolint: golint
type FetchRegistrationEntryResponse = datastore.FetchRegistrationEntryResponse     //nolint: golint
type GetNodeSelectorsRequest = datastore.GetNodeSelectorsRequest                   //nolint: golint
type GetNodeSelectorsResponse = datastore.GetNodeSelectorsResponse                 //nolint: golint
type JoinToken = datastore.JoinToken                                               //nolint: golint
type ListAttestedNodesRequest = datastore.ListAttestedNodesRequest                 //nolint: golint
type ListAttestedNodesResponse = datastore.ListAttestedNodesResponse               //nolint: golint
type ListBundlesRequest = datastore.ListBundlesRequest                             //nolint: golint
type ListBundlesResponse = datastore.ListBundlesResponse                           //nolint: golint
type ListRegistrationEntriesRequest = datastore.ListRegistrationEntriesRequest     //nolint: golint
type ListRegistrationEntriesResponse = datastore.ListRegistrationEntriesResponse   //nolint: golint
type NodeSelectors = datastore.NodeSelectors                                       //nolint: golint
type Pagination = datastore.Pagination                                             //nolint: golint
type PruneBundleRequest = datastore.PruneBundleRequest                             //nolint: golint
type PruneBundleResponse = datastore.PruneBundleResponse                           //nolint: golint
type PruneJoinTokensRequest = datastore.PruneJoinTokensRequest                     //nolint: golint
type PruneJoinTokensResponse = datastore.PruneJoinTokensResponse                   //nolint: golint
type PruneRegistrationEntriesRequest = datastore.PruneRegistrationEntriesRequest   //nolint: golint
type PruneRegistrationEntriesResponse = datastore.PruneRegistrationEntriesResponse //nolint: golint
type SetBundleRequest = datastore.SetBundleRequest                                 //nolint: golint
type SetBundleResponse = datastore.SetBundleResponse                               //nolint: golint
type SetNodeSelectorsRequest = datastore.SetNodeSelectorsRequest                   //nolint: golint
type SetNodeSelectorsResponse = datastore.SetNodeSelectorsResponse                 //nolint: golint
type UnimplementedDataStoreServer = datastore.UnimplementedDataStoreServer         //nolint: golint
type UpdateAttestedNodeRequest = datastore.UpdateAttestedNodeRequest               //nolint: golint
type UpdateAttestedNodeResponse = datastore.UpdateAttestedNodeResponse             //nolint: golint
type UpdateBundleRequest = datastore.UpdateBundleRequest                           //nolint: golint
type UpdateBundleResponse = datastore.UpdateBundleResponse                         //nolint: golint
type UpdateRegistrationEntryRequest = datastore.UpdateRegistrationEntryRequest     //nolint: golint
type UpdateRegistrationEntryResponse = datastore.UpdateRegistrationEntryResponse   //nolint: golint

const (
	Type                           = "DataStore"
	BySelectors_MATCH_EXACT        = datastore.BySelectors_MATCH_EXACT        //nolint: golint
	BySelectors_MATCH_SUBSET       = datastore.BySelectors_MATCH_SUBSET       //nolint: golint
	DeleteBundleRequest_DELETE     = datastore.DeleteBundleRequest_DELETE     //nolint: golint
	DeleteBundleRequest_DISSOCIATE = datastore.DeleteBundleRequest_DISSOCIATE //nolint: golint
	DeleteBundleRequest_RESTRICT   = datastore.DeleteBundleRequest_RESTRICT   //nolint: golint
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
	PruneBundle(context.Context, *PruneBundleRequest) (*PruneBundleResponse, error)
	PruneJoinTokens(context.Context, *PruneJoinTokensRequest) (*PruneJoinTokensResponse, error)
	PruneRegistrationEntries(context.Context, *PruneRegistrationEntriesRequest) (*PruneRegistrationEntriesResponse, error)
	SetBundle(context.Context, *SetBundleRequest) (*SetBundleResponse, error)
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
	PruneBundle(context.Context, *PruneBundleRequest) (*PruneBundleResponse, error)
	PruneJoinTokens(context.Context, *PruneJoinTokensRequest) (*PruneJoinTokensResponse, error)
	PruneRegistrationEntries(context.Context, *PruneRegistrationEntriesRequest) (*PruneRegistrationEntriesResponse, error)
	SetBundle(context.Context, *SetBundleRequest) (*SetBundleResponse, error)
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
	datastore.RegisterDataStoreServer(server, s.server)
	return s.server
}

// PluginClient is a catalog PluginClient implementation for the DataStore plugin.
var PluginClient catalog.PluginClient = pluginClient{}

type pluginClient struct{}

func (pluginClient) PluginType() string {
	return Type
}

func (pluginClient) NewPluginClient(conn *grpc.ClientConn) interface{} {
	return AdaptPluginClient(datastore.NewDataStoreClient(conn))
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

func (a pluginClientAdapter) PruneBundle(ctx context.Context, in *PruneBundleRequest) (*PruneBundleResponse, error) {
	return a.client.PruneBundle(ctx, in)
}

func (a pluginClientAdapter) PruneJoinTokens(ctx context.Context, in *PruneJoinTokensRequest) (*PruneJoinTokensResponse, error) {
	return a.client.PruneJoinTokens(ctx, in)
}

func (a pluginClientAdapter) PruneRegistrationEntries(ctx context.Context, in *PruneRegistrationEntriesRequest) (*PruneRegistrationEntriesResponse, error) {
	return a.client.PruneRegistrationEntries(ctx, in)
}

func (a pluginClientAdapter) SetBundle(ctx context.Context, in *SetBundleRequest) (*SetBundleResponse, error) {
	return a.client.SetBundle(ctx, in)
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
