package datastore

import (
	"net/rpc"
	"time"

	"google.golang.org/grpc"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/sri/control_plane/plugins/common/proto"
	"github.com/spiffe/sri/control_plane/plugins/data_store/proto"
)

const TimeFormat = time.RFC1123Z

// Handshake is a common handshake that is shared between noderesolution and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "DataStore",
	MagicCookieValue: "DataStore",
}

type DataStore interface {
	CreateFederatedEntry(request *sri_proto.CreateFederatedEntryRequest) (*sri_proto.CreateFederatedEntryResponse, error)
	ListFederatedEntry(request *sri_proto.ListFederatedEntryRequest) (*sri_proto.ListFederatedEntryResponse, error)
	UpdateFederatedEntry(request *sri_proto.UpdateFederatedEntryRequest) (*sri_proto.UpdateFederatedEntryResponse, error)
	DeleteFederatedEntry(request *sri_proto.DeleteFederatedEntryRequest) (*sri_proto.DeleteFederatedEntryResponse, error)

	CreateAttestedNodeEntry(request *sri_proto.CreateAttestedNodeEntryRequest) (*sri_proto.CreateAttestedNodeEntryResponse, error)
	FetchAttestedNodeEntry(request *sri_proto.FetchAttestedNodeEntryRequest) (*sri_proto.FetchAttestedNodeEntryResponse, error)
	FetchStaleNodeEntries(request *sri_proto.FetchStaleNodeEntriesRequest) (*sri_proto.FetchStaleNodeEntriesResponse, error)
	UpdateAttestedNodeEntry(request *sri_proto.UpdateAttestedNodeEntryRequest) (*sri_proto.UpdateAttestedNodeEntryResponse, error)
	DeleteAttestedNodeEntry(request *sri_proto.DeleteAttestedNodeEntryRequest) (*sri_proto.DeleteAttestedNodeEntryResponse, error)

	CreateNodeResolverMapEntry(request *sri_proto.CreateNodeResolverMapEntryRequest) (*sri_proto.CreateNodeResolverMapEntryResponse, error)
	FetchNodeResolverMapEntry(request *sri_proto.FetchNodeResolverMapEntryRequest) (*sri_proto.FetchNodeResolverMapEntryResponse, error)
	DeleteNodeResolverMapEntry(request *sri_proto.DeleteNodeResolverMapEntryRequest) (*sri_proto.DeleteNodeResolverMapEntryResponse, error)
	RectifyNodeResolverMapEntries(request *sri_proto.RectifyNodeResolverMapEntriesRequest) (*sri_proto.RectifyNodeResolverMapEntriesResponse, error)

	CreateRegistrationEntry(request *sri_proto.CreateRegistrationEntryRequest) (*sri_proto.CreateRegistrationEntryResponse, error)
	FetchRegistrationEntry(request *sri_proto.FetchRegistrationEntryRequest) (*sri_proto.FetchRegistrationEntryResponse, error)
	UpdateRegistrationEntry(request *sri_proto.UpdateRegistrationEntryRequest) (*sri_proto.UpdateRegistrationEntryResponse, error)
	DeleteRegistrationEntry(request *sri_proto.DeleteRegistrationEntryRequest) (*sri_proto.DeleteRegistrationEntryResponse, error)

	ListParentIDEntries(request *sri_proto.ListParentIDEntriesRequest) (*sri_proto.ListParentIDEntriesResponse, error)
	ListSelectorEntries(request *sri_proto.ListSelectorEntriesRequest) (*sri_proto.ListSelectorEntriesResponse, error)
	ListSpiffeEntries(request *sri_proto.ListSpiffeEntriesRequest) (*sri_proto.ListSpiffeEntriesResponse, error)

	Configure(request *common.ConfigureRequest) (*common.ConfigureResponse, error)
	GetPluginInfo(request *common.GetPluginInfoRequest) (*common.GetPluginInfoResponse, error)
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
	sri_proto.RegisterDataStoreServer(s, &GRPCServer{DataStoreImpl: p.DataStoreImpl})
	return nil
}

func (p DataStorePlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: sri_proto.NewDataStoreClient(c)}, nil
}
