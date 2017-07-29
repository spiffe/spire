package datastore

import (
	"net/rpc"

	"google.golang.org/grpc"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/control-plane/plugins/common/proto"
	"github.com/spiffe/control-plane/plugins/data_store/proto"
)

// Handshake is a common handshake that is shared between noderesolution and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "datastore_handshake",
	MagicCookieValue: "datastore",
}

// PluginMap is the map of plugins we can dispense.
var PluginMap = map[string]plugin.Plugin{
	"datastore": &DataStorePlugin{},
}

type DataStore interface {
	Configure(config string) ([]string, error)
	GetPluginInfo() (*common.GetPluginInfoResponse, error)
	CreateFederatedEntry(*proto.FederatedBundle) error
	ListFederatedEntry() (*proto.FederatedEntries, error)
	UpdateFederatedEntry(*proto.FederatedBundle) error
	DeleteFederatedEntry(*proto.Key) error
	CreateAttestedNodeEntry(*proto.AttestedNodeEntry) error
	FetchAttestedNodeEntry(*proto.Key) (*proto.AttestedNodeEntry, error)
	FetchStaleNodeEntries() (*proto.AttestedNodes, error)
	UpdateAttestedNodeEntry(*proto.AttestedNodeUpdate) error
	DeleteAttestedNodeEntry(*proto.Key) error
	CreateSelectorMapEntry(*proto.SelectorMapEntry) error
	FetchSelectorMapEntry(*proto.Key) error
	DeleteSelectorMapEntry(*proto.SelectorMapEntry) error
	CreateRegistrationEntry(*proto.RegisteredEntry) error
	FetchRegistrationEntry(*proto.RegisteredEntryKey) (*proto.RegisteredEntry, error)
	UpdateRegistrationEntry(*proto.RegisteredEntry) error
	DeleteRegistrationEntry(*proto.RegisteredEntryKey) error
	FetchGroupedRegistrationEntries(*proto.GroupedRegistrationKey) (*proto.RegisteredEntries, error)
	ListAttestorEntries(*proto.AttestorKey) (*proto.FederatedEntries, error)
	ListSelectorEntries(*proto.SelectorKey) (*proto.FederatedEntries, error)
	ListSpiffeEntries(*proto.Key) (*proto.FederatedEntries, error)
}

type DataStorePlugin struct {
	DataStoreImpl DataStore
}

func (p DataStorePlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p DataStorePlugin) Client(b *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p DataStorePlugin) GRPCServer(s *grpc.Server) error {
	proto.RegisterDataStoreServer(s, &GRPCServer{DataStoreImpl: p.DataStoreImpl})
	return nil
}

func (p DataStorePlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: proto.NewDataStoreClient(c)}, nil
}
