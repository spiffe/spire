package datastore

import (
	"github.com/spiffe/spire/proto/common"

	"golang.org/x/net/context"

	spi "github.com/spiffe/spire/proto/common/plugin"
)

type GRPCServer struct {
	DataStoreImpl DataStore
}

func (m *GRPCServer) CreateBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	res, err := m.DataStoreImpl.CreateBundle(req)
	return res, err
}

func (m *GRPCServer) UpdateBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	res, err := m.DataStoreImpl.UpdateBundle(req)
	return res, err
}

func (m *GRPCServer) AppendBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	res, err := m.DataStoreImpl.AppendBundle(req)
	return res, err
}

func (m *GRPCServer) DeleteBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	res, err := m.DataStoreImpl.DeleteBundle(req)
	return res, err
}

func (m *GRPCServer) FetchBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	res, err := m.DataStoreImpl.FetchBundle(req)
	return res, err
}

func (m *GRPCServer) ListBundles(ctx context.Context, req *common.Empty) (*Bundles, error) {
	res, err := m.DataStoreImpl.ListBundles(req)
	return res, err
}

func (m *GRPCServer) CreateAttestedNodeEntry(ctx context.Context, req *CreateAttestedNodeEntryRequest) (*CreateAttestedNodeEntryResponse, error) {
	res, err := m.DataStoreImpl.CreateAttestedNodeEntry(req)
	return res, err
}

//
//
//

func (m *GRPCServer) FetchAttestedNodeEntry(ctx context.Context, req *FetchAttestedNodeEntryRequest) (*FetchAttestedNodeEntryResponse, error) {
	res, err := m.DataStoreImpl.FetchAttestedNodeEntry(req)
	return res, err
}

func (m *GRPCServer) FetchStaleNodeEntries(ctx context.Context, req *FetchStaleNodeEntriesRequest) (*FetchStaleNodeEntriesResponse, error) {
	res, err := m.DataStoreImpl.FetchStaleNodeEntries(req)
	return res, err
}

func (m *GRPCServer) UpdateAttestedNodeEntry(ctx context.Context, req *UpdateAttestedNodeEntryRequest) (*UpdateAttestedNodeEntryResponse, error) {
	res, err := m.DataStoreImpl.UpdateAttestedNodeEntry(req)
	return res, err
}

func (m *GRPCServer) DeleteAttestedNodeEntry(ctx context.Context, req *DeleteAttestedNodeEntryRequest) (*DeleteAttestedNodeEntryResponse, error) {
	res, err := m.DataStoreImpl.DeleteAttestedNodeEntry(req)
	return res, err
}

//
//
//

func (m *GRPCServer) CreateNodeResolverMapEntry(ctx context.Context, req *CreateNodeResolverMapEntryRequest) (*CreateNodeResolverMapEntryResponse, error) {
	res, err := m.DataStoreImpl.CreateNodeResolverMapEntry(req)
	return res, err
}

func (m *GRPCServer) FetchNodeResolverMapEntry(ctx context.Context, req *FetchNodeResolverMapEntryRequest) (*FetchNodeResolverMapEntryResponse, error) {
	res, err := m.DataStoreImpl.FetchNodeResolverMapEntry(req)
	return res, err
}

func (m *GRPCServer) DeleteNodeResolverMapEntry(ctx context.Context, req *DeleteNodeResolverMapEntryRequest) (*DeleteNodeResolverMapEntryResponse, error) {
	res, err := m.DataStoreImpl.DeleteNodeResolverMapEntry(req)
	return res, err
}

func (m *GRPCServer) RectifyNodeResolverMapEntries(ctx context.Context, req *RectifyNodeResolverMapEntriesRequest) (*RectifyNodeResolverMapEntriesResponse, error) {
	res, err := m.DataStoreImpl.RectifyNodeResolverMapEntries(req)
	return res, err
}

//
//
//

func (m *GRPCServer) CreateRegistrationEntry(ctx context.Context, req *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error) {
	res, err := m.DataStoreImpl.CreateRegistrationEntry(req)
	return res, err
}

func (m *GRPCServer) FetchRegistrationEntry(ctx context.Context, req *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error) {
	res, err := m.DataStoreImpl.FetchRegistrationEntry(req)
	return res, err
}

func (m *GRPCServer) FetchRegistrationEntries(ctx context.Context, req *common.Empty) (*FetchRegistrationEntriesResponse, error) {
	res, err := m.DataStoreImpl.FetchRegistrationEntries(req)
	return res, err
}

func (m *GRPCServer) UpdateRegistrationEntry(ctx context.Context, req *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error) {
	res, err := m.DataStoreImpl.UpdateRegistrationEntry(req)
	return res, err
}

func (m *GRPCServer) DeleteRegistrationEntry(ctx context.Context, req *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error) {
	res, err := m.DataStoreImpl.DeleteRegistrationEntry(req)
	return res, err
}

//
//
//

func (m *GRPCServer) ListParentIDEntries(ctx context.Context, req *ListParentIDEntriesRequest) (*ListParentIDEntriesResponse, error) {
	res, err := m.DataStoreImpl.ListParentIDEntries(req)
	return res, err
}

func (m *GRPCServer) ListSelectorEntries(ctx context.Context, req *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error) {
	res, err := m.DataStoreImpl.ListSelectorEntries(req)
	return res, err
}

func (m *GRPCServer) ListMatchingEntries(ctx context.Context, req *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error) {
	return m.DataStoreImpl.ListMatchingEntries(req)
}

func (m *GRPCServer) ListSpiffeEntries(ctx context.Context, req *ListSpiffeEntriesRequest) (*ListSpiffeEntriesResponse, error) {
	res, err := m.DataStoreImpl.ListSpiffeEntries(req)
	return res, err
}

//
//
//

func (m *GRPCServer) RegisterToken(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	return m.DataStoreImpl.RegisterToken(req)
}

func (m *GRPCServer) FetchToken(ctx context.Context, req *JoinToken) (*JoinToken, error) {
	return m.DataStoreImpl.FetchToken(req)
}

func (m *GRPCServer) DeleteToken(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	return m.DataStoreImpl.DeleteToken(req)
}

func (m *GRPCServer) PruneTokens(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	return m.DataStoreImpl.PruneTokens(req)
}

//
//
//

func (m *GRPCServer) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	res, err := m.DataStoreImpl.Configure(req)
	return res, err
}

func (m *GRPCServer) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	res, err := m.DataStoreImpl.GetPluginInfo(req)
	return res, err
}

//
//
//

type GRPCClient struct {
	client DataStoreClient
}

func (m *GRPCClient) CreateBundle(req *Bundle) (*Bundle, error) {
	res, err := m.client.CreateBundle(context.Background(), req)
	return res, err
}

func (m *GRPCClient) UpdateBundle(req *Bundle) (*Bundle, error) {
	res, err := m.client.UpdateBundle(context.Background(), req)
	return res, err
}

func (m *GRPCClient) AppendBundle(req *Bundle) (*Bundle, error) {
	res, err := m.client.AppendBundle(context.Background(), req)
	return res, err
}

func (m *GRPCClient) DeleteBundle(req *Bundle) (*Bundle, error) {
	res, err := m.client.DeleteBundle(context.Background(), req)
	return res, err
}

func (m *GRPCClient) FetchBundle(req *Bundle) (*Bundle, error) {
	res, err := m.client.FetchBundle(context.Background(), req)
	return res, err
}

func (m *GRPCClient) ListBundles(req *common.Empty) (*Bundles, error) {
	res, err := m.client.ListBundles(context.Background(), req)
	return res, err
}

//
//
//

func (m *GRPCClient) CreateAttestedNodeEntry(req *CreateAttestedNodeEntryRequest) (*CreateAttestedNodeEntryResponse, error) {
	res, err := m.client.CreateAttestedNodeEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) FetchAttestedNodeEntry(req *FetchAttestedNodeEntryRequest) (*FetchAttestedNodeEntryResponse, error) {
	res, err := m.client.FetchAttestedNodeEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) FetchStaleNodeEntries(req *FetchStaleNodeEntriesRequest) (*FetchStaleNodeEntriesResponse, error) {
	res, err := m.client.FetchStaleNodeEntries(context.Background(), req)
	return res, err
}

func (m *GRPCClient) UpdateAttestedNodeEntry(req *UpdateAttestedNodeEntryRequest) (*UpdateAttestedNodeEntryResponse, error) {
	res, err := m.client.UpdateAttestedNodeEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) DeleteAttestedNodeEntry(req *DeleteAttestedNodeEntryRequest) (*DeleteAttestedNodeEntryResponse, error) {
	res, err := m.client.DeleteAttestedNodeEntry(context.Background(), req)
	return res, err
}

//
//
//

func (m *GRPCClient) CreateNodeResolverMapEntry(req *CreateNodeResolverMapEntryRequest) (*CreateNodeResolverMapEntryResponse, error) {
	res, err := m.client.CreateNodeResolverMapEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) FetchNodeResolverMapEntry(req *FetchNodeResolverMapEntryRequest) (*FetchNodeResolverMapEntryResponse, error) {
	res, err := m.client.FetchNodeResolverMapEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) DeleteNodeResolverMapEntry(req *DeleteNodeResolverMapEntryRequest) (*DeleteNodeResolverMapEntryResponse, error) {
	res, err := m.client.DeleteNodeResolverMapEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) RectifyNodeResolverMapEntries(req *RectifyNodeResolverMapEntriesRequest) (*RectifyNodeResolverMapEntriesResponse, error) {
	res, err := m.client.RectifyNodeResolverMapEntries(context.Background(), req)
	return res, err
}

//
//
//

func (m *GRPCClient) CreateRegistrationEntry(req *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error) {
	res, err := m.client.CreateRegistrationEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) FetchRegistrationEntry(req *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error) {
	res, err := m.client.FetchRegistrationEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) FetchRegistrationEntries(req *common.Empty) (*FetchRegistrationEntriesResponse, error) {
	res, err := m.client.FetchRegistrationEntries(context.Background(), req)
	return res, err
}

func (m *GRPCClient) UpdateRegistrationEntry(req *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error) {
	res, err := m.client.UpdateRegistrationEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) DeleteRegistrationEntry(req *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error) {
	res, err := m.client.DeleteRegistrationEntry(context.Background(), req)
	return res, err
}

//
//
//

func (m *GRPCClient) ListParentIDEntries(req *ListParentIDEntriesRequest) (*ListParentIDEntriesResponse, error) {
	res, err := m.client.ListParentIDEntries(context.Background(), req)
	return res, err
}

func (m *GRPCClient) ListSelectorEntries(req *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error) {
	res, err := m.client.ListSelectorEntries(context.Background(), req)
	return res, err
}

func (m *GRPCClient) ListMatchingEntries(req *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error) {
	return m.client.ListMatchingEntries(context.Background(), req)
}

func (m *GRPCClient) ListSpiffeEntries(req *ListSpiffeEntriesRequest) (*ListSpiffeEntriesResponse, error) {
	res, err := m.client.ListSpiffeEntries(context.Background(), req)
	return res, err
}

//
//
//

func (m *GRPCClient) RegisterToken(req *JoinToken) (*common.Empty, error) {
	return m.client.RegisterToken(context.Background(), req)
}

func (m *GRPCClient) FetchToken(req *JoinToken) (*JoinToken, error) {
	return m.client.FetchToken(context.Background(), req)
}

func (m *GRPCClient) DeleteToken(req *JoinToken) (*common.Empty, error) {
	return m.client.DeleteToken(context.Background(), req)
}

func (m *GRPCClient) PruneTokens(req *JoinToken) (*common.Empty, error) {
	return m.client.PruneTokens(context.Background(), req)
}

//
//
//

func (m *GRPCClient) Configure(req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	res, err := m.client.Configure(context.Background(), req)
	return res, err
}

func (m *GRPCClient) GetPluginInfo(req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	res, err := m.client.GetPluginInfo(context.Background(), req)
	return res, err
}
