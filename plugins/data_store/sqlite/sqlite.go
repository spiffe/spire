package sqlite

import (
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/control-plane/plugins/data_store"
	"github.com/spiffe/control-plane/plugins/data_store/proto"
)

type SqlitePlugin struct{}

func (SqlitePlugin) CreateFederatedEntry(federatedBundle *proto.FederatedBundle) error {
	return nil
}

func (SqlitePlugin) ListFederatedEntry() (*proto.FederatedEntries, error) {
	return nil, nil
}

func (SqlitePlugin) UpdateFederatedEntry(federatedBundle *proto.FederatedBundle) error {
	return nil
}

func (SqlitePlugin) DeleteFederatedEntry(key *proto.Key) error {
	return nil
}

func (SqlitePlugin) CreateAttestedNodeEntry(attestedNodeEntry *proto.AttestedNodeEntry) error {
	return nil
}

func (SqlitePlugin) FetchAttestedNodeEntry(*proto.Key) (*proto.AttestedNodeEntry, error) {
	return nil, nil
}

func (SqlitePlugin) FetchStaleNodeEntries() (*proto.AttestedNodes, error) {
	return nil, nil
}

func (SqlitePlugin) UpdateAttestedNodeEntry(attestedNodeUpdate *proto.AttestedNodeUpdate) error {
	return nil
}

func (SqlitePlugin) DeleteAttestedNodeEntry(key *proto.Key) error {
	return nil
}

func (SqlitePlugin) CreateSelectorMapEntry(selectorMapEntry *proto.SelectorMapEntry) error {
	return nil
}

func (SqlitePlugin) FetchSelectorMapEntry(key *proto.Key) error {
	return nil
}

func (SqlitePlugin) DeleteSelectorMapEntry(selectorMapEntry *proto.SelectorMapEntry) error {
	return nil
}

func (SqlitePlugin) CreateRegistrationEntry(registeredEntry *proto.RegisteredEntry) error {
	return nil
}

func (SqlitePlugin) FetchRegistrationEntry(registeredEntryKey *proto.RegisteredEntryKey) (*proto.RegisteredEntry, error) {
	return nil, nil
}

func (SqlitePlugin) UpdateRegistrationEntry(registeredEntry *proto.RegisteredEntry) error {
	return nil
}

func (SqlitePlugin) DeleteRegistrationEntry(registeredEntryKey *proto.RegisteredEntryKey) error {
	return nil
}

func (SqlitePlugin) FetchGroupedRegistrationEntries(groupedRegistrationKey *proto.GroupedRegistrationKey) (*proto.RegisteredEntries, error) {
	return nil, nil
}

func (SqlitePlugin) ListAttestorEntries(attestorKey *proto.AttestorKey) (*proto.FederatedEntries, error) {
	return nil, nil
}

func (SqlitePlugin) ListSelectorEntries(selectorKey *proto.SelectorKey) (*proto.FederatedEntries, error) {
	return nil, nil
}

func (SqlitePlugin) ListSpiffeEntries(federatedEntries *proto.Key) (*proto.FederatedEntries, error) {
	return nil, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: datastore.Handshake,
		Plugins: map[string]plugin.Plugin{
			"datastore": datastore.DataStorePlugin{DataStoreImpl: &SqlitePlugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
