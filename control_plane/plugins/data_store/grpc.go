package datastore

import (
	common "github.com/spiffe/control-plane/plugins/common/proto"
	"github.com/spiffe/control-plane/plugins/data_store/proto"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	DataStoreImpl DataStore
}

func (m *GRPCServer) CreateFederatedEntry(ctx context.Context, req *proto.CreateFederatedEntryRequest) (*proto.CreateFederatedEntryResponse, error) {
	res, err := m.DataStoreImpl.CreateFederatedEntry(req)
	return res, err
}

func (m *GRPCServer) ListFederatedEntry(ctx context.Context, req *proto.ListFederatedEntryRequest) (*proto.ListFederatedEntryResponse, error) {
	res, err := m.DataStoreImpl.ListFederatedEntry(req)
	return res, err
}

func (m *GRPCServer) UpdateFederatedEntry(ctx context.Context, req *proto.UpdateFederatedEntryRequest) (*proto.UpdateFederatedEntryResponse, error) {
	res, err := m.DataStoreImpl.UpdateFederatedEntry(req)
	return res, err
}

func (m *GRPCServer) DeleteFederatedEntry(ctx context.Context, req *proto.DeleteFederatedEntryRequest) (*proto.DeleteFederatedEntryResponse, error) {
	res, err := m.DataStoreImpl.DeleteFederatedEntry(req)
	return res, err
}

func (m *GRPCServer) CreateAttestedNodeEntry(ctx context.Context, req *proto.CreateAttestedNodeEntryRequest) (*proto.CreateAttestedNodeEntryResponse, error) {
	res, err := m.DataStoreImpl.CreateAttestedNodeEntry(req)
	return res, err
}

//

func (m *GRPCServer) FetchAttestedNodeEntry(ctx context.Context, req *proto.FetchAttestedNodeEntryRequest) (*proto.FetchAttestedNodeEntryResponse, error) {
	res, err := m.DataStoreImpl.FetchAttestedNodeEntry(req)
	return res, err
}

func (m *GRPCServer) FetchStaleNodeEntries(ctx context.Context, req *proto.FetchStaleNodeEntriesRequest) (*proto.FetchStaleNodeEntriesResponse, error) {
	res, err := m.DataStoreImpl.FetchStaleNodeEntries(req)
	return res, err
}

func (m *GRPCServer) UpdateAttestedNodeEntry(ctx context.Context, req *proto.UpdateAttestedNodeEntryRequest) (*proto.UpdateAttestedNodeEntryResponse, error) {
	res, err := m.DataStoreImpl.UpdateAttestedNodeEntry(req)
	return res, err
}

func (m *GRPCServer) DeleteAttestedNodeEntry(ctx context.Context, req *proto.DeleteAttestedNodeEntryRequest) (*proto.DeleteAttestedNodeEntryResponse, error) {
	res, err := m.DataStoreImpl.DeleteAttestedNodeEntry(req)
	return res, err
}

//

func (m *GRPCServer) CreateNodeResolverMapEntry(ctx context.Context, req *proto.CreateNodeResolverMapEntryRequest) (*proto.CreateNodeResolverMapEntryResponse, error) {
	res, err := m.DataStoreImpl.CreateNodeResolverMapEntry(req)
	return res, err
}

func (m *GRPCServer) FetchNodeResolverMapEntry(ctx context.Context, req *proto.FetchNodeResolverMapEntryRequest) (*proto.FetchNodeResolverMapEntryResponse, error) {
	res, err := m.DataStoreImpl.FetchNodeResolverMapEntry(req)
	return res, err
}

func (m *GRPCServer) DeleteNodeResolverMapEntry(ctx context.Context, req *proto.DeleteNodeResolverMapEntryRequest) (*proto.DeleteNodeResolverMapEntryResponse, error) {
	res, err := m.DataStoreImpl.DeleteNodeResolverMapEntry(req)
	return res, err
}

func (m *GRPCServer) RectifyNodeResolverMapEntries(ctx context.Context, req *proto.RectifyNodeResolverMapEntriesRequest) (*proto.RectifyNodeResolverMapEntriesResponse, error) {
	res, err := m.DataStoreImpl.RectifyNodeResolverMapEntries(req)
	return res, err
}

//

func (m *GRPCServer) CreateRegistrationEntry(ctx context.Context, req *proto.CreateRegistrationEntryRequest) (*proto.CreateRegistrationEntryResponse, error) {
	res, err := m.DataStoreImpl.CreateRegistrationEntry(req)
	return res, err
}

func (m *GRPCServer) FetchRegistrationEntry(ctx context.Context, req *proto.FetchRegistrationEntryRequest) (*proto.FetchRegistrationEntryResponse, error) {
	res, err := m.DataStoreImpl.FetchRegistrationEntry(req)
	return res, err
}

func (m *GRPCServer) UpdateRegistrationEntry(ctx context.Context, req *proto.UpdateRegistrationEntryRequest) (*proto.UpdateRegistrationEntryResponse, error) {
	res, err := m.DataStoreImpl.UpdateRegistrationEntry(req)
	return res, err
}

func (m *GRPCServer) DeleteRegistrationEntry(ctx context.Context, req *proto.DeleteRegistrationEntryRequest) (*proto.DeleteRegistrationEntryResponse, error) {
	res, err := m.DataStoreImpl.DeleteRegistrationEntry(req)
	return res, err
}

//

func (m *GRPCServer) ListParentIDEntries(ctx context.Context, req *proto.ListParentIDEntriesRequest) (*proto.ListParentIDEntriesResponse, error) {
	res, err := m.DataStoreImpl.ListParentIDEntries(req)
	return res, err
}

func (m *GRPCServer) ListSelectorEntries(ctx context.Context, req *proto.ListSelectorEntriesRequest) (*proto.ListSelectorEntriesResponse, error) {
	res, err := m.DataStoreImpl.ListSelectorEntries(req)
	return res, err
}

func (m *GRPCServer) ListSpiffeEntries(ctx context.Context, req *proto.ListSpiffeEntriesRequest) (*proto.ListSpiffeEntriesResponse, error) {
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
	client proto.DataStoreClient
}

func (m *GRPCClient) CreateFederatedEntry(req *proto.CreateFederatedEntryRequest) (*proto.CreateFederatedEntryResponse, error) {
	res, err := m.client.CreateFederatedEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) ListFederatedEntry(req *proto.ListFederatedEntryRequest) (*proto.ListFederatedEntryResponse, error) {
	res, err := m.client.ListFederatedEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) UpdateFederatedEntry(req *proto.UpdateFederatedEntryRequest) (*proto.UpdateFederatedEntryResponse, error) {
	res, err := m.client.UpdateFederatedEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) DeleteFederatedEntry(req *proto.DeleteFederatedEntryRequest) (*proto.DeleteFederatedEntryResponse, error) {
	res, err := m.client.DeleteFederatedEntry(context.Background(), req)
	return res, err
}

//

func (m *GRPCClient) CreateAttestedNodeEntry(req *proto.CreateAttestedNodeEntryRequest) (*proto.CreateAttestedNodeEntryResponse, error) {
	res, err := m.client.CreateAttestedNodeEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) FetchAttestedNodeEntry(req *proto.FetchAttestedNodeEntryRequest) (*proto.FetchAttestedNodeEntryResponse, error) {
	res, err := m.client.FetchAttestedNodeEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) FetchStaleNodeEntries(req *proto.FetchStaleNodeEntriesRequest) (*proto.FetchStaleNodeEntriesResponse, error) {
	res, err := m.client.FetchStaleNodeEntries(context.Background(), req)
	return res, err
}

func (m *GRPCClient) UpdateAttestedNodeEntryEntry(req *proto.UpdateAttestedNodeEntryRequest) (*proto.UpdateAttestedNodeEntryResponse, error) {
	res, err := m.client.UpdateAttestedNodeEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) DeleteAttestedNodeEntry(req *proto.DeleteAttestedNodeEntryRequest) (*proto.DeleteAttestedNodeEntryResponse, error) {
	res, err := m.client.DeleteAttestedNodeEntry(context.Background(), req)
	return res, err
}

//

func (m *GRPCClient) CreateNodeResolverMapEntry(req *proto.CreateNodeResolverMapEntryRequest) (*proto.CreateNodeResolverMapEntryResponse, error) {
	res, err := m.client.CreateNodeResolverMapEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) FetchNodeResolverMapEntry(req *proto.FetchNodeResolverMapEntryRequest) (*proto.FetchNodeResolverMapEntryResponse, error) {
	res, err := m.client.FetchNodeResolverMapEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) DeleteNodeResolverMapEntry(req *proto.DeleteNodeResolverMapEntryRequest) (*proto.DeleteNodeResolverMapEntryResponse, error) {
	res, err := m.client.DeleteNodeResolverMapEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) RectifyNodeResolverMapEntries(req *proto.RectifyNodeResolverMapEntriesRequest) (*proto.RectifyNodeResolverMapEntriesResponse, error) {
	res, err := m.client.RectifyNodeResolverMapEntries(context.Background(), req)
	return res, err
}

//

func (m *GRPCClient) CreateRegistrationEntry(req *proto.CreateRegistrationEntryRequest) (*proto.CreateRegistrationEntryResponse, error) {
	res, err := m.client.CreateRegistrationEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) FetchRegistrationEntry(req *proto.FetchRegistrationEntryRequest) (*proto.FetchRegistrationEntryResponse, error) {
	res, err := m.client.FetchRegistrationEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) UpdateRegistrationEntry(req *proto.UpdateRegistrationEntryRequest) (*proto.UpdateRegistrationEntryResponse, error) {
	res, err := m.client.UpdateRegistrationEntry(context.Background(), req)
	return res, err
}

func (m *GRPCClient) DeleteRegistrationEntry(req *proto.DeleteRegistrationEntryRequest) (*proto.DeleteRegistrationEntryResponse, error) {
	res, err := m.client.DeleteRegistrationEntry(context.Background(), req)
	return res, err
}

//

func (m *GRPCClient) ListParentIDEntries(req *proto.ListParentIDEntriesRequest) (*proto.ListParentIDEntriesResponse, error) {
	res, err := m.client.ListParentIDEntries(context.Background(), req)
	return res, err
}

func (m *GRPCClient) ListSelectorEntries(req *proto.ListSelectorEntriesRequest) (*proto.ListSelectorEntriesResponse, error) {
	res, err := m.client.ListSelectorEntries(context.Background(), req)
	return res, err
}

func (m *GRPCClient) ListSpiffeEntries(req *proto.ListSpiffeEntriesRequest) (*proto.ListSpiffeEntriesResponse, error) {
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
