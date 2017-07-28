package datastore

import (
	"github.com/spiffe/control-plane/plugins/data_store/proto"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	DataStoreImpl DataStore
}

func (m *GRPCServer) CreateFederatedEntry(ctx context.Context, federatedBundle *proto.FederatedBundle) (*proto.Empty, error) {
	err := m.DataStoreImpl.CreateFederatedEntry(federatedBundle)
	return &proto.Empty{}, err
}

func (m *GRPCServer) ListFederatedEntry(ctx context.Context, _ *proto.Empty) (*proto.FederatedEntries, error) {
	response, err := m.DataStoreImpl.ListFederatedEntry()
	return response, err
}

func (m *GRPCServer) UpdateFederatedEntry(ctx context.Context, federatedBundle *proto.FederatedBundle) (*proto.Empty, error) {
	err := m.DataStoreImpl.UpdateFederatedEntry(federatedBundle)
	return &proto.Empty{}, err
}

func (m *GRPCServer) DeleteFederatedEntry(ctx context.Context, key *proto.Key) (*proto.Empty, error) {
	err := m.DataStoreImpl.DeleteFederatedEntry(key)
	return &proto.Empty{}, err
}

func (m *GRPCServer) CreateAttestedNodeEntry(ctx context.Context, attestedNodeEntry *proto.AttestedNodeEntry) (*proto.Empty, error) {
	err := m.DataStoreImpl.CreateAttestedNodeEntry(attestedNodeEntry)
	return &proto.Empty{}, err
}

func (m *GRPCServer) FetchAttestedNodeEntry(ctx context.Context, key *proto.Key) (*proto.AttestedNodeEntry, error) {
	response, err := m.DataStoreImpl.FetchAttestedNodeEntry(key)
	return response, err
}

func (m *GRPCServer) FetchStaleNodeEntries(ctx context.Context, _ *proto.Empty) (*proto.AttestedNodes, error) {
	response, err := m.DataStoreImpl.FetchStaleNodeEntries()
	return response, err
}
func (m *GRPCServer) UpdateAttestedNodeEntry(ctx context.Context, attestedNodeUpdate *proto.AttestedNodeUpdate) (*proto.Empty, error) {
	err := m.DataStoreImpl.UpdateAttestedNodeEntry(attestedNodeUpdate)
	return &proto.Empty{}, err
}

func (m *GRPCServer) DeleteAttestedNodeEntry(ctx context.Context, key *proto.Key) (*proto.Empty, error) {
	err := m.DataStoreImpl.DeleteAttestedNodeEntry(key)
	return &proto.Empty{}, err
}

func (m *GRPCServer) CreateSelectorMapEntry(ctx context.Context, selectorMapEntry *proto.SelectorMapEntry) (*proto.Empty, error) {
	err := m.DataStoreImpl.CreateSelectorMapEntry(selectorMapEntry)
	return &proto.Empty{}, err
}

func (m *GRPCServer) FetchSelectorMapEntry(ctx context.Context, key *proto.Key) (*proto.Empty, error) {
	err := m.DataStoreImpl.FetchSelectorMapEntry(key)
	return &proto.Empty{}, err
}

func (m *GRPCServer) DeleteSelectorMapEntry(ctx context.Context, selectorMapEntry *proto.SelectorMapEntry) (*proto.Empty, error) {
	err := m.DataStoreImpl.DeleteSelectorMapEntry(selectorMapEntry)
	return &proto.Empty{}, err
}

func (m *GRPCServer) CreateRegistrationEntry(ctx context.Context, registeredEntry *proto.RegisteredEntry) (*proto.Empty, error) {
	err := m.DataStoreImpl.CreateRegistrationEntry(registeredEntry)
	return &proto.Empty{}, err
}

func (m *GRPCServer) FetchRegistrationEntry(ctx context.Context, registeredEntryKey *proto.RegisteredEntryKey) (*proto.RegisteredEntry, error) {
	response, err := m.DataStoreImpl.FetchRegistrationEntry(registeredEntryKey)
	return response, err
}

func (m *GRPCServer) UpdateRegistrationEntry(ctx context.Context, registeredEntry *proto.RegisteredEntry) (*proto.Empty, error) {
	err := m.DataStoreImpl.UpdateRegistrationEntry(registeredEntry)
	return &proto.Empty{}, err
}

func (m *GRPCServer) DeleteRegistrationEntry(ctx context.Context, registeredEntryKey *proto.RegisteredEntryKey) (*proto.Empty, error) {
	err := m.DataStoreImpl.DeleteRegistrationEntry(registeredEntryKey)
	return &proto.Empty{}, err
}

func (m *GRPCServer) FetchGroupedRegistrationEntries(ctx context.Context, groupedRegistrationKey *proto.GroupedRegistrationKey) (*proto.RegisteredEntries, error) {
	response, err := m.DataStoreImpl.FetchGroupedRegistrationEntries(groupedRegistrationKey)
	return response, err
}

func (m *GRPCServer) ListAttestorEntries(ctx context.Context, attestorKey *proto.AttestorKey) (*proto.FederatedEntries, error) {
	response, err := m.DataStoreImpl.ListAttestorEntries(attestorKey)
	return response, err
}

func (m *GRPCServer) ListSelectorEntries(ctx context.Context, selectorKey *proto.SelectorKey) (*proto.FederatedEntries, error) {
	response, err := m.DataStoreImpl.ListSelectorEntries(selectorKey)
	return response, err
}

func (m *GRPCServer) ListSpiffeEntries(ctx context.Context, key *proto.Key) (*proto.FederatedEntries, error) {
	response, err := m.DataStoreImpl.ListSpiffeEntries(key)
	return response, err
}

type GRPCClient struct {
	client proto.DataStoreClient
}

func (m *GRPCClient) CreateFederatedEntry(federatedBundle *proto.FederatedBundle) error {
	_, err := m.client.CreateFederatedEntry(context.Background(), federatedBundle)
	return err
}

func (m *GRPCClient) ListFederatedEntry(empty *proto.Empty) (*proto.FederatedEntries, error) {
	response, err := m.client.ListFederatedEntry(context.Background(), empty)
	return response, err
}

func (m *GRPCClient) UpdateFederatedEntry(ctx context.Context, federatedBundle *proto.FederatedBundle) (*proto.Empty, error) {
	response, err := m.client.UpdateFederatedEntry(context.Background(), federatedBundle)
	return response, err
}

func (m *GRPCClient) DeleteFederatedEntry(ctx context.Context, key *proto.Key) (*proto.Empty, error) {
	response, err := m.client.DeleteFederatedEntry(context.Background(), key)
	return response, err
}

func (m *GRPCClient) CreateAttestedNodeEntry(ctx context.Context, attestedNodeEntry *proto.AttestedNodeEntry) (*proto.Empty, error) {
	response, err := m.client.CreateAttestedNodeEntry(context.Background(), attestedNodeEntry)
	return response, err
}

func (m *GRPCClient) FetchAttestedNodeEntry(ctx context.Context, key *proto.Key) (*proto.AttestedNodeEntry, error) {
	response, err := m.client.FetchAttestedNodeEntry(context.Background(), key)
	return response, err
}

func (m *GRPCClient) FetchStaleNodeEntries(ctx context.Context, empty *proto.Empty) (*proto.AttestedNodes, error) {
	response, err := m.client.FetchStaleNodeEntries(context.Background(), empty)
	return response, err
}
func (m *GRPCClient) UpdateAttestedNodeEntry(ctx context.Context, attestedNodeUpdate *proto.AttestedNodeUpdate) (*proto.Empty, error) {
	response, err := m.client.UpdateAttestedNodeEntry(context.Background(), attestedNodeUpdate)
	return response, err
}

func (m *GRPCClient) DeleteAttestedNodeEntry(ctx context.Context, key *proto.Key) (*proto.Empty, error) {
	response, err := m.client.DeleteAttestedNodeEntry(context.Background(), key)
	return response, err
}

func (m *GRPCClient) CreateSelectorMapEntry(ctx context.Context, selectorMapEntry *proto.SelectorMapEntry) (*proto.Empty, error) {
	response, err := m.client.CreateSelectorMapEntry(context.Background(), selectorMapEntry)
	return response, err
}

func (m *GRPCClient) FetchSelectorMapEntry(ctx context.Context, key *proto.Key) (*proto.Empty, error) {
	response, err := m.client.FetchSelectorMapEntry(context.Background(), key)
	return response, err
}

func (m *GRPCClient) DeleteSelectorMapEntry(ctx context.Context, selectorMapEntry *proto.SelectorMapEntry) (*proto.Empty, error) {
	response, err := m.client.DeleteSelectorMapEntry(context.Background(), selectorMapEntry)
	return response, err
}

func (m *GRPCClient) CreateRegistrationEntry(ctx context.Context, registeredEntry *proto.RegisteredEntry) (*proto.Empty, error) {
	response, err := m.client.CreateRegistrationEntry(context.Background(), registeredEntry)
	return response, err
}

func (m *GRPCClient) FetchRegistrationEntry(ctx context.Context, registeredEntryKey *proto.RegisteredEntryKey) (*proto.RegisteredEntry, error) {
	response, err := m.client.FetchRegistrationEntry(context.Background(), registeredEntryKey)
	return response, err
}

func (m *GRPCClient) UpdateRegistrationEntry(ctx context.Context, registeredEntry *proto.RegisteredEntry) (*proto.Empty, error) {
	response, err := m.client.UpdateRegistrationEntry(context.Background(), registeredEntry)
	return response, err
}

func (m *GRPCClient) DeleteRegistrationEntry(ctx context.Context, registeredEntryKey *proto.RegisteredEntryKey) (*proto.Empty, error) {
	response, err := m.client.DeleteRegistrationEntry(context.Background(), registeredEntryKey)
	return response, err
}

func (m *GRPCClient) FetchGroupedRegistrationEntries(ctx context.Context, groupedRegistrationKey *proto.GroupedRegistrationKey) (*proto.RegisteredEntries, error) {
	response, err := m.client.FetchGroupedRegistrationEntries(context.Background(), groupedRegistrationKey)
	return response, err
}

func (m *GRPCClient) ListAttestorEntries(ctx context.Context, attestorKey *proto.AttestorKey) (*proto.FederatedEntries, error) {
	response, err := m.client.ListAttestorEntries(context.Background(), attestorKey)
	return response, err
}

func (m *GRPCClient) ListSelectorEntries(ctx context.Context, selectorKey *proto.SelectorKey) (*proto.FederatedEntries, error) {
	response, err := m.client.ListSelectorEntries(context.Background(), selectorKey)
	return response, err
}

func (m *GRPCClient) ListSpiffeEntries(ctx context.Context, key *proto.Key) (*proto.FederatedEntries, error) {
	response, err := m.client.ListSpiffeEntries(context.Background(), key)
	return response, err
}
