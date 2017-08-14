package datastore

import (
	"net/rpc"

	"google.golang.org/grpc"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/sri/control_plane/plugins/common/proto"
	"github.com/spiffe/sri/control_plane/plugins/data_store/proto"
)

// Handshake is a common handshake that is shared between noderesolution and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "DataStore",
	MagicCookieValue: "DataStore",
}

type DataStore interface {
	CreateFederatedEntry(request *control_plane_proto.CreateFederatedEntryRequest) (*control_plane_proto.CreateFederatedEntryResponse, error)
	ListFederatedEntry(request *control_plane_proto.ListFederatedEntryRequest) (*control_plane_proto.ListFederatedEntryResponse, error)
	UpdateFederatedEntry(request *control_plane_proto.UpdateFederatedEntryRequest) (*control_plane_proto.UpdateFederatedEntryResponse, error)
	DeleteFederatedEntry(request *control_plane_proto.DeleteFederatedEntryRequest) (*control_plane_proto.DeleteFederatedEntryResponse, error)

	CreateAttestedNodeEntry(request *control_plane_proto.CreateAttestedNodeEntryRequest) (*control_plane_proto.CreateAttestedNodeEntryResponse, error)
	FetchAttestedNodeEntry(request *control_plane_proto.FetchAttestedNodeEntryRequest) (*control_plane_proto.FetchAttestedNodeEntryResponse, error)
	FetchStaleNodeEntries(request *control_plane_proto.FetchStaleNodeEntriesRequest) (*control_plane_proto.FetchStaleNodeEntriesResponse, error)
	UpdateAttestedNodeEntry(request *control_plane_proto.UpdateAttestedNodeEntryRequest) (*control_plane_proto.UpdateAttestedNodeEntryResponse, error)
	DeleteAttestedNodeEntry(request *control_plane_proto.DeleteAttestedNodeEntryRequest) (*control_plane_proto.DeleteAttestedNodeEntryResponse, error)

	CreateNodeResolverMapEntry(request *control_plane_proto.CreateNodeResolverMapEntryRequest) (*control_plane_proto.CreateNodeResolverMapEntryResponse, error)
	FetchNodeResolverMapEntry(request *control_plane_proto.FetchNodeResolverMapEntryRequest) (*control_plane_proto.FetchNodeResolverMapEntryResponse, error)
	DeleteNodeResolverMapEntry(request *control_plane_proto.DeleteNodeResolverMapEntryRequest) (*control_plane_proto.DeleteNodeResolverMapEntryResponse, error)
	RectifyNodeResolverMapEntries(request *control_plane_proto.RectifyNodeResolverMapEntriesRequest) (*control_plane_proto.RectifyNodeResolverMapEntriesResponse, error)

	CreateRegistrationEntry(request *control_plane_proto.CreateRegistrationEntryRequest) (*control_plane_proto.CreateRegistrationEntryResponse, error)
	FetchRegistrationEntry(request *control_plane_proto.FetchRegistrationEntryRequest) (*control_plane_proto.FetchRegistrationEntryResponse, error)
	UpdateRegistrationEntry(request *control_plane_proto.UpdateRegistrationEntryRequest) (*control_plane_proto.UpdateRegistrationEntryResponse, error)
	DeleteRegistrationEntry(request *control_plane_proto.DeleteRegistrationEntryRequest) (*control_plane_proto.DeleteRegistrationEntryResponse, error)

	ListParentIDEntries(request *control_plane_proto.ListParentIDEntriesRequest) (*control_plane_proto.ListParentIDEntriesResponse, error)
	ListSelectorEntries(request *control_plane_proto.ListSelectorEntriesRequest) (*control_plane_proto.ListSelectorEntriesResponse, error)
	ListSpiffeEntries(request *control_plane_proto.ListSpiffeEntriesRequest) (*control_plane_proto.ListSpiffeEntriesResponse, error)

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
	control_plane_proto.RegisterDataStoreServer(s, &GRPCServer{DataStoreImpl: p.DataStoreImpl})
	return nil
}

func (p DataStorePlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: control_plane_proto.NewDataStoreClient(c)}, nil
}
