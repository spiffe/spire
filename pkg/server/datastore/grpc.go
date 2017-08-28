package datastore

import (
	"github.com/spiffe/sri/pkg/common/plugin"
	"golang.org/x/net/context"
)

type grpcServer struct {
	delegate Interface
}

func (m *grpcServer) CreateFederatedEntry(ctx context.Context, req *CreateFederatedEntryRequest) (*CreateFederatedEntryResponse, error) {
	res, err := m.delegate.CreateFederatedEntry(req)
	return res, err
}

func (m *grpcServer) ListFederatedEntry(ctx context.Context, req *ListFederatedEntryRequest) (*ListFederatedEntryResponse, error) {
	res, err := m.delegate.ListFederatedEntry(req)
	return res, err
}

func (m *grpcServer) UpdateFederatedEntry(ctx context.Context, req *UpdateFederatedEntryRequest) (*UpdateFederatedEntryResponse, error) {
	res, err := m.delegate.UpdateFederatedEntry(req)
	return res, err
}

func (m *grpcServer) DeleteFederatedEntry(ctx context.Context, req *DeleteFederatedEntryRequest) (*DeleteFederatedEntryResponse, error) {
	res, err := m.delegate.DeleteFederatedEntry(req)
	return res, err
}

func (m *grpcServer) CreateAttestedNodeEntry(ctx context.Context, req *CreateAttestedNodeEntryRequest) (*CreateAttestedNodeEntryResponse, error) {
	res, err := m.delegate.CreateAttestedNodeEntry(req)
	return res, err
}

//

func (m *grpcServer) FetchAttestedNodeEntry(ctx context.Context, req *FetchAttestedNodeEntryRequest) (*FetchAttestedNodeEntryResponse, error) {
	res, err := m.delegate.FetchAttestedNodeEntry(req)
	return res, err
}

func (m *grpcServer) FetchStaleNodeEntries(ctx context.Context, req *FetchStaleNodeEntriesRequest) (*FetchStaleNodeEntriesResponse, error) {
	res, err := m.delegate.FetchStaleNodeEntries(req)
	return res, err
}

func (m *grpcServer) UpdateAttestedNodeEntry(ctx context.Context, req *UpdateAttestedNodeEntryRequest) (*UpdateAttestedNodeEntryResponse, error) {
	res, err := m.delegate.UpdateAttestedNodeEntry(req)
	return res, err
}

func (m *grpcServer) DeleteAttestedNodeEntry(ctx context.Context, req *DeleteAttestedNodeEntryRequest) (*DeleteAttestedNodeEntryResponse, error) {
	res, err := m.delegate.DeleteAttestedNodeEntry(req)
	return res, err
}

//

func (m *grpcServer) CreateNodeResolverMapEntry(ctx context.Context, req *CreateNodeResolverMapEntryRequest) (*CreateNodeResolverMapEntryResponse, error) {
	res, err := m.delegate.CreateNodeResolverMapEntry(req)
	return res, err
}

func (m *grpcServer) FetchNodeResolverMapEntry(ctx context.Context, req *FetchNodeResolverMapEntryRequest) (*FetchNodeResolverMapEntryResponse, error) {
	res, err := m.delegate.FetchNodeResolverMapEntry(req)
	return res, err
}

func (m *grpcServer) DeleteNodeResolverMapEntry(ctx context.Context, req *DeleteNodeResolverMapEntryRequest) (*DeleteNodeResolverMapEntryResponse, error) {
	res, err := m.delegate.DeleteNodeResolverMapEntry(req)
	return res, err
}

func (m *grpcServer) RectifyNodeResolverMapEntries(ctx context.Context, req *RectifyNodeResolverMapEntriesRequest) (*RectifyNodeResolverMapEntriesResponse, error) {
	res, err := m.delegate.RectifyNodeResolverMapEntries(req)
	return res, err
}

//

func (m *grpcServer) CreateRegistrationEntry(ctx context.Context, req *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error) {
	res, err := m.delegate.CreateRegistrationEntry(req)
	return res, err
}

func (m *grpcServer) FetchRegistrationEntry(ctx context.Context, req *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error) {
	res, err := m.delegate.FetchRegistrationEntry(req)
	return res, err
}

func (m *grpcServer) UpdateRegistrationEntry(ctx context.Context, req *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error) {
	res, err := m.delegate.UpdateRegistrationEntry(req)
	return res, err
}

func (m *grpcServer) DeleteRegistrationEntry(ctx context.Context, req *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error) {
	res, err := m.delegate.DeleteRegistrationEntry(req)
	return res, err
}

//

func (m *grpcServer) ListParentIDEntries(ctx context.Context, req *ListParentIDEntriesRequest) (*ListParentIDEntriesResponse, error) {
	res, err := m.delegate.ListParentIDEntries(req)
	return res, err
}

func (m *grpcServer) ListSelectorEntries(ctx context.Context, req *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error) {
	res, err := m.delegate.ListSelectorEntries(req)
	return res, err
}

func (m *grpcServer) ListSpiffeEntries(ctx context.Context, req *ListSpiffeEntriesRequest) (*ListSpiffeEntriesResponse, error) {
	res, err := m.delegate.ListSpiffeEntries(req)
	return res, err
}

//

func (m *grpcServer) Configure(ctx context.Context, req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	res, err := m.delegate.Configure(req)
	return res, err
}

func (m *grpcServer) GetPluginInfo(ctx context.Context, req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	res, err := m.delegate.GetPluginInfo(req)
	return res, err
}

type grpcClient struct {
	client DataStoreClient
}

func (m *grpcClient) CreateFederatedEntry(req *CreateFederatedEntryRequest) (*CreateFederatedEntryResponse, error) {
	res, err := m.client.CreateFederatedEntry(context.Background(), req)
	return res, err
}

func (m *grpcClient) ListFederatedEntry(req *ListFederatedEntryRequest) (*ListFederatedEntryResponse, error) {
	res, err := m.client.ListFederatedEntry(context.Background(), req)
	return res, err
}

func (m *grpcClient) UpdateFederatedEntry(req *UpdateFederatedEntryRequest) (*UpdateFederatedEntryResponse, error) {
	res, err := m.client.UpdateFederatedEntry(context.Background(), req)
	return res, err
}

func (m *grpcClient) DeleteFederatedEntry(req *DeleteFederatedEntryRequest) (*DeleteFederatedEntryResponse, error) {
	res, err := m.client.DeleteFederatedEntry(context.Background(), req)
	return res, err
}

//

func (m *grpcClient) CreateAttestedNodeEntry(req *CreateAttestedNodeEntryRequest) (*CreateAttestedNodeEntryResponse, error) {
	res, err := m.client.CreateAttestedNodeEntry(context.Background(), req)
	return res, err
}

func (m *grpcClient) FetchAttestedNodeEntry(req *FetchAttestedNodeEntryRequest) (*FetchAttestedNodeEntryResponse, error) {
	res, err := m.client.FetchAttestedNodeEntry(context.Background(), req)
	return res, err
}

func (m *grpcClient) FetchStaleNodeEntries(req *FetchStaleNodeEntriesRequest) (*FetchStaleNodeEntriesResponse, error) {
	res, err := m.client.FetchStaleNodeEntries(context.Background(), req)
	return res, err
}

func (m *grpcClient) UpdateAttestedNodeEntry(req *UpdateAttestedNodeEntryRequest) (*UpdateAttestedNodeEntryResponse, error) {
	res, err := m.client.UpdateAttestedNodeEntry(context.Background(), req)
	return res, err
}

func (m *grpcClient) DeleteAttestedNodeEntry(req *DeleteAttestedNodeEntryRequest) (*DeleteAttestedNodeEntryResponse, error) {
	res, err := m.client.DeleteAttestedNodeEntry(context.Background(), req)
	return res, err
}

//

func (m *grpcClient) CreateNodeResolverMapEntry(req *CreateNodeResolverMapEntryRequest) (*CreateNodeResolverMapEntryResponse, error) {
	res, err := m.client.CreateNodeResolverMapEntry(context.Background(), req)
	return res, err
}

func (m *grpcClient) FetchNodeResolverMapEntry(req *FetchNodeResolverMapEntryRequest) (*FetchNodeResolverMapEntryResponse, error) {
	res, err := m.client.FetchNodeResolverMapEntry(context.Background(), req)
	return res, err
}

func (m *grpcClient) DeleteNodeResolverMapEntry(req *DeleteNodeResolverMapEntryRequest) (*DeleteNodeResolverMapEntryResponse, error) {
	res, err := m.client.DeleteNodeResolverMapEntry(context.Background(), req)
	return res, err
}

func (m *grpcClient) RectifyNodeResolverMapEntries(req *RectifyNodeResolverMapEntriesRequest) (*RectifyNodeResolverMapEntriesResponse, error) {
	res, err := m.client.RectifyNodeResolverMapEntries(context.Background(), req)
	return res, err
}

//

func (m *grpcClient) CreateRegistrationEntry(req *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error) {
	res, err := m.client.CreateRegistrationEntry(context.Background(), req)
	return res, err
}

func (m *grpcClient) FetchRegistrationEntry(req *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error) {
	res, err := m.client.FetchRegistrationEntry(context.Background(), req)
	return res, err
}

func (m *grpcClient) UpdateRegistrationEntry(req *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error) {
	res, err := m.client.UpdateRegistrationEntry(context.Background(), req)
	return res, err
}

func (m *grpcClient) DeleteRegistrationEntry(req *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error) {
	res, err := m.client.DeleteRegistrationEntry(context.Background(), req)
	return res, err
}

//

func (m *grpcClient) ListParentIDEntries(req *ListParentIDEntriesRequest) (*ListParentIDEntriesResponse, error) {
	res, err := m.client.ListParentIDEntries(context.Background(), req)
	return res, err
}

func (m *grpcClient) ListSelectorEntries(req *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error) {
	res, err := m.client.ListSelectorEntries(context.Background(), req)
	return res, err
}

func (m *grpcClient) ListSpiffeEntries(req *ListSpiffeEntriesRequest) (*ListSpiffeEntriesResponse, error) {
	res, err := m.client.ListSpiffeEntries(context.Background(), req)
	return res, err
}

//

func (m *grpcClient) Configure(req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	res, err := m.client.Configure(context.Background(), req)
	return res, err
}

func (m *grpcClient) GetPluginInfo(req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	res, err := m.client.GetPluginInfo(context.Background(), req)
	return res, err
}
