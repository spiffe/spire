package datastore

import (
	"github.com/spiffe/spire/proto/common"

	"golang.org/x/net/context"

	spi "github.com/spiffe/spire/proto/common/plugin"
)

//
//
//

type GRPCClient struct {
	client DataStoreClient
}

func (m *GRPCClient) CreateBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	res, err := m.client.CreateBundle(ctx, req)
	return res, err
}

func (m *GRPCClient) UpdateBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	res, err := m.client.UpdateBundle(ctx, req)
	return res, err
}

func (m *GRPCClient) AppendBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	res, err := m.client.AppendBundle(ctx, req)
	return res, err
}

func (m *GRPCClient) DeleteBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	res, err := m.client.DeleteBundle(ctx, req)
	return res, err
}

func (m *GRPCClient) FetchBundle(ctx context.Context, req *Bundle) (*Bundle, error) {
	res, err := m.client.FetchBundle(ctx, req)
	return res, err
}

func (m *GRPCClient) ListBundles(ctx context.Context, req *common.Empty) (*Bundles, error) {
	res, err := m.client.ListBundles(ctx, req)
	return res, err
}

//
//
//

func (m *GRPCClient) CreateAttestedNodeEntry(ctx context.Context, req *CreateAttestedNodeEntryRequest) (*CreateAttestedNodeEntryResponse, error) {
	res, err := m.client.CreateAttestedNodeEntry(ctx, req)
	return res, err
}

func (m *GRPCClient) FetchAttestedNodeEntry(ctx context.Context, req *FetchAttestedNodeEntryRequest) (*FetchAttestedNodeEntryResponse, error) {
	res, err := m.client.FetchAttestedNodeEntry(ctx, req)
	return res, err
}

func (m *GRPCClient) FetchStaleNodeEntries(ctx context.Context, req *FetchStaleNodeEntriesRequest) (*FetchStaleNodeEntriesResponse, error) {
	res, err := m.client.FetchStaleNodeEntries(ctx, req)
	return res, err
}

func (m *GRPCClient) UpdateAttestedNodeEntry(ctx context.Context, req *UpdateAttestedNodeEntryRequest) (*UpdateAttestedNodeEntryResponse, error) {
	res, err := m.client.UpdateAttestedNodeEntry(ctx, req)
	return res, err
}

func (m *GRPCClient) DeleteAttestedNodeEntry(ctx context.Context, req *DeleteAttestedNodeEntryRequest) (*DeleteAttestedNodeEntryResponse, error) {
	res, err := m.client.DeleteAttestedNodeEntry(ctx, req)
	return res, err
}

//
//
//

func (m *GRPCClient) CreateNodeResolverMapEntry(ctx context.Context, req *CreateNodeResolverMapEntryRequest) (*CreateNodeResolverMapEntryResponse, error) {
	res, err := m.client.CreateNodeResolverMapEntry(ctx, req)
	return res, err
}

func (m *GRPCClient) FetchNodeResolverMapEntry(ctx context.Context, req *FetchNodeResolverMapEntryRequest) (*FetchNodeResolverMapEntryResponse, error) {
	res, err := m.client.FetchNodeResolverMapEntry(ctx, req)
	return res, err
}

func (m *GRPCClient) DeleteNodeResolverMapEntry(ctx context.Context, req *DeleteNodeResolverMapEntryRequest) (*DeleteNodeResolverMapEntryResponse, error) {
	res, err := m.client.DeleteNodeResolverMapEntry(ctx, req)
	return res, err
}

func (m *GRPCClient) RectifyNodeResolverMapEntries(ctx context.Context, req *RectifyNodeResolverMapEntriesRequest) (*RectifyNodeResolverMapEntriesResponse, error) {
	res, err := m.client.RectifyNodeResolverMapEntries(ctx, req)
	return res, err
}

//
//
//

func (m *GRPCClient) CreateRegistrationEntry(ctx context.Context, req *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error) {
	res, err := m.client.CreateRegistrationEntry(ctx, req)
	return res, err
}

func (m *GRPCClient) FetchRegistrationEntry(ctx context.Context, req *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error) {
	res, err := m.client.FetchRegistrationEntry(ctx, req)
	return res, err
}

func (m *GRPCClient) FetchRegistrationEntries(ctx context.Context, req *common.Empty) (*FetchRegistrationEntriesResponse, error) {
	res, err := m.client.FetchRegistrationEntries(ctx, req)
	return res, err
}

func (m *GRPCClient) UpdateRegistrationEntry(ctx context.Context, req *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error) {
	res, err := m.client.UpdateRegistrationEntry(ctx, req)
	return res, err
}

func (m *GRPCClient) DeleteRegistrationEntry(ctx context.Context, req *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error) {
	res, err := m.client.DeleteRegistrationEntry(ctx, req)
	return res, err
}

//
//
//

func (m *GRPCClient) ListParentIDEntries(ctx context.Context, req *ListParentIDEntriesRequest) (*ListParentIDEntriesResponse, error) {
	res, err := m.client.ListParentIDEntries(ctx, req)
	return res, err
}

func (m *GRPCClient) ListSelectorEntries(ctx context.Context, req *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error) {
	res, err := m.client.ListSelectorEntries(ctx, req)
	return res, err
}

func (m *GRPCClient) ListMatchingEntries(ctx context.Context, req *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error) {
	return m.client.ListMatchingEntries(ctx, req)
}

func (m *GRPCClient) ListSpiffeEntries(ctx context.Context, req *ListSpiffeEntriesRequest) (*ListSpiffeEntriesResponse, error) {
	res, err := m.client.ListSpiffeEntries(ctx, req)
	return res, err
}

//
//
//

func (m *GRPCClient) RegisterToken(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	return m.client.RegisterToken(ctx, req)
}

func (m *GRPCClient) FetchToken(ctx context.Context, req *JoinToken) (*JoinToken, error) {
	return m.client.FetchToken(ctx, req)
}

func (m *GRPCClient) DeleteToken(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	return m.client.DeleteToken(ctx, req)
}

func (m *GRPCClient) PruneTokens(ctx context.Context, req *JoinToken) (*common.Empty, error) {
	return m.client.PruneTokens(ctx, req)
}

//
//
//

func (m *GRPCClient) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	res, err := m.client.Configure(ctx, req)
	return res, err
}

func (m *GRPCClient) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	res, err := m.client.GetPluginInfo(ctx, req)
	return res, err
}
