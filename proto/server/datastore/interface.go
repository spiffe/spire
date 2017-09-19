package datastore

import (
	"net/rpc"
	"time"

	"google.golang.org/grpc"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/pkg/common/plugin"
)

const TimeFormat = time.RFC1123Z

// Handshake is a common handshake that is shared between noderesolution and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "DataStore",
	MagicCookieValue: "DataStore",
}

type DataStore interface {
	CreateFederatedEntry(request *CreateFederatedEntryRequest) (*CreateFederatedEntryResponse, error)
	ListFederatedEntry(request *ListFederatedEntryRequest) (*ListFederatedEntryResponse, error)
	UpdateFederatedEntry(request *UpdateFederatedEntryRequest) (*UpdateFederatedEntryResponse, error)
	DeleteFederatedEntry(request *DeleteFederatedEntryRequest) (*DeleteFederatedEntryResponse, error)

	CreateAttestedNodeEntry(request *CreateAttestedNodeEntryRequest) (*CreateAttestedNodeEntryResponse, error)
	FetchAttestedNodeEntry(request *FetchAttestedNodeEntryRequest) (*FetchAttestedNodeEntryResponse, error)
	FetchStaleNodeEntries(request *FetchStaleNodeEntriesRequest) (*FetchStaleNodeEntriesResponse, error)
	UpdateAttestedNodeEntry(request *UpdateAttestedNodeEntryRequest) (*UpdateAttestedNodeEntryResponse, error)
	DeleteAttestedNodeEntry(request *DeleteAttestedNodeEntryRequest) (*DeleteAttestedNodeEntryResponse, error)

	CreateNodeResolverMapEntry(request *CreateNodeResolverMapEntryRequest) (*CreateNodeResolverMapEntryResponse, error)
	FetchNodeResolverMapEntry(request *FetchNodeResolverMapEntryRequest) (*FetchNodeResolverMapEntryResponse, error)
	DeleteNodeResolverMapEntry(request *DeleteNodeResolverMapEntryRequest) (*DeleteNodeResolverMapEntryResponse, error)
	RectifyNodeResolverMapEntries(request *RectifyNodeResolverMapEntriesRequest) (*RectifyNodeResolverMapEntriesResponse, error)

	CreateRegistrationEntry(request *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error)
	FetchRegistrationEntry(request *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error)
	UpdateRegistrationEntry(request *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error)
	DeleteRegistrationEntry(request *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error)

	ListParentIDEntries(request *ListParentIDEntriesRequest) (*ListParentIDEntriesResponse, error)
	ListSelectorEntries(request *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error)
	ListSpiffeEntries(request *ListSpiffeEntriesRequest) (*ListSpiffeEntriesResponse, error)

	Configure(request *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error)
	GetPluginInfo(request *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error)
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
	RegisterDataStoreServer(s, &GRPCServer{DataStoreImpl: p.DataStoreImpl})
	return nil
}

func (p DataStorePlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewDataStoreClient(c)}, nil
}
