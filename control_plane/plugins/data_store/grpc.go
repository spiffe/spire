package datastore

import (
	common "github.com/spiffe/sri/common/plugins/common/proto"
	"github.com/spiffe/sri/control_plane/plugins/data_store/proto"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	DataStoreImpl DataStore
}

func (m *GRPCServer) CreateFederatedEntry(ctx context.Context, req *sri_proto.CreateFederatedEntryRequest) (*sri_proto.CreateFederatedEntryResponse, error) {
	res, err := m.DataStoreImpl.CreateFederatedEntry(req)
	return res, err
}

func (m *GRPCServer) ListFederatedEntry(ctx context.Context, req *sri_proto.ListFederatedEntryRequest) (*sri_proto.ListFederatedEntryResponse, error) {
	res, err := m.DataStoreImpl.ListFederatedEntry(req)
	return res, err
}

func (m *GRPCServer) UpdateFederatedEntry(ctx context.Context, req *sri_proto.UpdateFederatedEntryRequest) (*sri_proto.UpdateFederatedEntryResponse, error) {
	res, err := m.DataStoreImpl.UpdateFederatedEntry(req)
	return res, err
}

func (m *GRPCServer) DeleteFederatedEntry(ctx context.Context, req *sri_proto.DeleteFederatedEntryRequest) (*sri_proto.DeleteFederatedEntryResponse, error) {
	res, err := m.DataStoreImpl.DeleteFederatedEntry(req)
	return res, err
}

func (m *GRPCServer) CreateAttestedNodeEntry(ctx context.Context, req *sri_proto.CreateAttestedNodeEntryRequest) (*sri_proto.CreateAttestedNodeEntryResponse, error) {
	res, err := m.DataStoreImpl.CreateAttestedNodeEntry(req)
	return res, err
}

//

func (m *GRPCServer) FetchAttestedNodeEntry(ctx context.Context, req *sri_proto.FetchAttestedNodeEntryRequest) (*sri_proto.FetchAttestedNodeEntryResponse, error) {
	res, err := m.DataStoreImpl.FetchAttestedNodeEntry(req)
	return res, err
}

func (m *GRPCServer) FetchStaleNodeEntries(ctx context.Context, req *sri_proto.FetchStaleNodeEntriesRequest) (*sri_proto.FetchStaleNodeEntriesResponse, error) {
	res, err := m.DataStoreImpl.FetchStaleNodeEntries(req)
	return res, err
}

func (m *GRPCServer) UpdateAttestedNodeEntry(ctx context.Context, req *sri_proto.UpdateAttestedNodeEntryRequest) (*sri_proto.UpdateAttestedNodeEntryResponse, error) {
	res, err := m.DataStoreImpl.UpdateAttestedNodeEntry(req)
	return res, err
}

func (m *GRPCServer) DeleteAttestedNodeEntry(ctx context.Context, req *sri_proto.DeleteAttestedNodeEntryRequest) (*sri_proto.DeleteAttestedNodeEntryResponse, error) {
	res, err := m.DataStoreImpl.DeleteAttestedNodeEntry(req)
	return res, err
}

//

func (m *GRPCServer) CreateNodeResolverMapEntry(ctx context.Context, req *sri_proto.CreateNodeResolverMapEntryRequest) (*sri_proto.CreateNodeResolverMapEntryResponse, error) {
	res, err := m.DataStoreImpl.CreateNodeResolverMapEntry(req)
	return res, err
}

func (m *GRPCServer) FetchNodeResolverMapEntry(ctx context.Context, req *sri_proto.FetchNodeResolverMapEntryRequest) (*sri_proto.FetchNodeResolverMapEntryResponse, error) {
	res, err := m.DataStoreImpl.FetchNodeResolverMapEntry(req)
	return res, err
}

func (m *GRPCServer) DeleteNodeResolverMapEntry(ctx context.Context, req *sri_proto.DeleteNodeResolverMapEntryRequest) (*sri_proto.DeleteNodeResolverMapEntryResponse, error) {
	res, err := m.DataStoreImpl.DeleteNodeResolverMapEntry(req)
	return res, err
}

func (m *GRPCServer) RectifyNodeResolverMapEntries(ctx context.Context, req *sri_proto.RectifyNodeResolverMapEntriesRequest) (*sri_proto.RectifyNodeResolverMapEntriesResponse, error) {
	res, err := m.DataStoreImpl.RectifyNodeResolverMapEntries(req)
	return res, err
}

//

func (m *GRPCServer) CreateRegistrationEntry(ctx context.Context, req *sri_proto.CreateRegistrationEntryRequest) (*sri_proto.CreateRegistrationEntryResponse, error) {
	res, err := m.DataStoreImpl.CreateRegistrationEntry(req)
	return res, err
}

func (m *GRPCServer) FetchRegistrationEntry(ctx context.Context, req *sri_proto.FetchRegistrationEntryRequest) (*sri_proto.FetchRegistrationEntryResponse, error) {
	res, err := m.DataStoreImpl.FetchRegistrationEntry(req)
	return res, err
}

func (m *GRPCServer) UpdateRegistrationEntry(ctx context.Context, req *sri_proto.UpdateRegistrationEntryRequest) (*sri_proto.UpdateRegistrationEntryResponse, error) {
	res, err := m.DataStoreImpl.UpdateRegistrationEntry(req)
	return res, err
}

func (m *GRPCServer) DeleteRegistrationEntry(ctx context.Context, req *sri_proto.DeleteRegistrationEntryRequest) (*sri_proto.DeleteRegistrationEntryResponse, error) {
	res, err := m.DataStoreImpl.DeleteRegistrationEntry(req)
	return res, err
}

//

func (m *GRPCServer) ListParentIDEntries(ctx context.Context, req *sri_proto.ListParentIDEntriesRequest) (*sri_proto.ListParentIDEntriesResponse, error) {
	res, err := m.DataStoreImpl.ListParentIDEntries(req)
	return res, err
}

func (m *GRPCServer) ListSelectorEntries(ctx context.Context, req *sri_proto.ListSelectorEntriesRequest) (*sri_proto.ListSelectorEntriesResponse, error) {
	res, err := m.DataStoreImpl.ListSelectorEntries(req)
	return res, err
}

func (m *GRPCServer) ListSpiffeEntries(ctx context.Context, req *sri_proto.ListSpiffeEntriesRequest) (*sri_proto.ListSpiffeEntriesResponse, error) {
	res, err := m.DataStoreImpl.ListSpiffeEntries(req)
	return res, err
}

//

func (m *GRPCServer) Configure(ctx context.Context, req *common.ConfigureRequest) (*common.ConfigureResponse, error) {
	res, err := m.DataStoreImpl.Configure(req)
	return res, err
}

func (m *GRPCServer) GetPluginInfo(ctx context.Context, req *common.GetPluginInfoRequest) (*common.GetPluginInfoResponse, error) {
	res, err := m.DataStoreImpl.GetPluginInfo(req)
	return res, err
}

type GRPCClient struct {
	client sri_proto.DataStoreClient
}

func (m *GRPCClient) CreateFederatedEntry(req *sri_proto.CreateFederatedEntryRequest) (*sri_proto.CreateFederatedEntryResponse, error) {
	res, err := m.client.CreateFederatedEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) ListFederatedEntry(req *sri_proto.ListFederatedEntryRequest) (*sri_proto.ListFederatedEntryResponse, error) {
	res, err := m.client.ListFederatedEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) UpdateFederatedEntry(req *sri_proto.UpdateFederatedEntryRequest) (*sri_proto.UpdateFederatedEntryResponse, error) {
	res, err := m.client.UpdateFederatedEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) DeleteFederatedEntry(req *sri_proto.DeleteFederatedEntryRequest) (*sri_proto.DeleteFederatedEntryResponse, error) {
	res, err := m.client.DeleteFederatedEntry(context.Background(), req)
	return res, err
}

//

func (m *GRPCClient) CreateAttestedNodeEntry(req *sri_proto.CreateAttestedNodeEntryRequest) (*sri_proto.CreateAttestedNodeEntryResponse, error) {
	res, err := m.client.CreateAttestedNodeEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) FetchAttestedNodeEntry(req *sri_proto.FetchAttestedNodeEntryRequest) (*sri_proto.FetchAttestedNodeEntryResponse, error) {
	res, err := m.client.FetchAttestedNodeEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) FetchStaleNodeEntries(req *sri_proto.FetchStaleNodeEntriesRequest) (*sri_proto.FetchStaleNodeEntriesResponse, error) {
	res, err := m.client.FetchStaleNodeEntries(context.Background(), req)
	return res, err
}

func (m *GRPCClient) UpdateAttestedNodeEntryEntry(req *sri_proto.UpdateAttestedNodeEntryRequest) (*sri_proto.UpdateAttestedNodeEntryResponse, error) {
	res, err := m.client.UpdateAttestedNodeEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) DeleteAttestedNodeEntry(req *sri_proto.DeleteAttestedNodeEntryRequest) (*sri_proto.DeleteAttestedNodeEntryResponse, error) {
	res, err := m.client.DeleteAttestedNodeEntry(context.Background(), req)
	return res, err
}

//

func (m *GRPCClient) CreateNodeResolverMapEntry(req *sri_proto.CreateNodeResolverMapEntryRequest) (*sri_proto.CreateNodeResolverMapEntryResponse, error) {
	res, err := m.client.CreateNodeResolverMapEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) FetchNodeResolverMapEntry(req *sri_proto.FetchNodeResolverMapEntryRequest) (*sri_proto.FetchNodeResolverMapEntryResponse, error) {
	res, err := m.client.FetchNodeResolverMapEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) DeleteNodeResolverMapEntry(req *sri_proto.DeleteNodeResolverMapEntryRequest) (*sri_proto.DeleteNodeResolverMapEntryResponse, error) {
	res, err := m.client.DeleteNodeResolverMapEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) RectifyNodeResolverMapEntries(req *sri_proto.RectifyNodeResolverMapEntriesRequest) (*sri_proto.RectifyNodeResolverMapEntriesResponse, error) {
	res, err := m.client.RectifyNodeResolverMapEntries(context.Background(), req)
	return res, err
}

//

func (m *GRPCClient) CreateRegistrationEntry(req *sri_proto.CreateRegistrationEntryRequest) (*sri_proto.CreateRegistrationEntryResponse, error) {
	res, err := m.client.CreateRegistrationEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) FetchRegistrationEntry(req *sri_proto.FetchRegistrationEntryRequest) (*sri_proto.FetchRegistrationEntryResponse, error) {
	res, err := m.client.FetchRegistrationEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) UpdateRegistrationEntry(req *sri_proto.UpdateRegistrationEntryRequest) (*sri_proto.UpdateRegistrationEntryResponse, error) {
	res, err := m.client.UpdateRegistrationEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) DeleteRegistrationEntry(req *sri_proto.DeleteRegistrationEntryRequest) (*sri_proto.DeleteRegistrationEntryResponse, error) {
	res, err := m.client.DeleteRegistrationEntry(context.Background(), req)
	return res, err
}

//

func (m *GRPCClient) ListParentIDEntries(req *sri_proto.ListParentIDEntriesRequest) (*sri_proto.ListParentIDEntriesResponse, error) {
	res, err := m.client.ListParentIDEntries(context.Background(), req)
	return res, err
}

func (m *GRPCClient) ListSelectorEntries(req *sri_proto.ListSelectorEntriesRequest) (*sri_proto.ListSelectorEntriesResponse, error) {
	res, err := m.client.ListSelectorEntries(context.Background(), req)
	return res, err
}

func (m *GRPCClient) ListSpiffeEntries(req *sri_proto.ListSpiffeEntriesRequest) (*sri_proto.ListSpiffeEntriesResponse, error) {
	res, err := m.client.ListSpiffeEntries(context.Background(), req)
	return res, err
}

//

func (m *GRPCClient) Configure(req *common.ConfigureRequest) (*common.ConfigureResponse, error) {
	res, err := m.client.Configure(context.Background(), req)
	return res, err
}

func (m *GRPCClient) GetPluginInfo(req *common.GetPluginInfoRequest) (*common.GetPluginInfoResponse, error) {
	res, err := m.client.GetPluginInfo(context.Background(), req)
	return res, err
}
