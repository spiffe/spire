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
	MagicCookieKey:   "DataStore",
	MagicCookieValue: "DataStore",
}

type DataStore interface {
	CreateFederatedEntry(request *proto.CreateFederatedEntryRequest) (*proto.CreateFederatedEntryResponse, error)
	ListFederatedEntry(request *proto.ListFederatedEntryRequest) (*proto.ListFederatedEntryResponse, error)
	UpdateFederatedEntry(request *proto.UpdateFederatedEntryRequest) (*proto.UpdateFederatedEntryResponse, error)
	DeleteFederatedEntry(request *proto.DeleteFederatedEntryRequest) (*proto.DeleteFederatedEntryResponse, error)

	CreateAttestedNodeEntry(request *proto.CreateAttestedNodeEntryRequest) (*proto.CreateAttestedNodeEntryResponse, error)
	FetchAttestedNodeEntry(request *proto.FetchAttestedNodeEntryRequest) (*proto.FetchAttestedNodeEntryResponse, error)
	FetchStaleNodeEntries(request *proto.FetchStaleNodeEntriesRequest) (*proto.FetchStaleNodeEntriesResponse, error)
	UpdateAttestedNodeEntry(request *proto.UpdateAttestedNodeEntryRequest) (*proto.UpdateAttestedNodeEntryResponse, error)
	DeleteAttestedNodeEntry(request *proto.DeleteAttestedNodeEntryRequest) (*proto.DeleteAttestedNodeEntryResponse, error)

	CreateNodeResolverMapEntry(request *proto.CreateNodeResolverMapEntryRequest) (*proto.CreateNodeResolverMapEntryResponse, error)
	FetchNodeResolverMapEntry(request *proto.FetchNodeResolverMapEntryRequest) (*proto.FetchNodeResolverMapEntryResponse, error)
	DeleteNodeResolverMapEntry(request *proto.DeleteNodeResolverMapEntryRequest) (*proto.DeleteNodeResolverMapEntryResponse, error)
	RectifyNodeResolverMapEntries(request *proto.RectifyNodeResolverMapEntriesRequest) (*proto.RectifyNodeResolverMapEntriesResponse, error)

	CreateRegistrationEntry(request *proto.CreateRegistrationEntryRequest) (*proto.CreateRegistrationEntryResponse, error)
	FetchRegistrationEntry(request *proto.FetchRegistrationEntryRequest) (*proto.FetchRegistrationEntryResponse, error)
	UpdateRegistrationEntry(request *proto.UpdateRegistrationEntryRequest) (*proto.UpdateRegistrationEntryResponse, error)
	DeleteRegistrationEntry(request *proto.DeleteRegistrationEntryRequest) (*proto.DeleteRegistrationEntryResponse, error)

	ListParentIDEntries(request *proto.ListParentIDEntriesRequest) (*proto.ListParentIDEntriesResponse, error)
	ListSelectorEntries(request *proto.ListSelectorEntriesRequest) (*proto.ListSelectorEntriesResponse, error)
	ListSpiffeEntries(request *proto.ListSpiffeEntriesRequest) (*proto.ListSpiffeEntriesResponse, error)

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
	proto.RegisterDataStoreServer(s, &GRPCServer{DataStoreImpl: p.DataStoreImpl})
	return nil
}

func (p DataStorePlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: proto.NewDataStoreClient(c)}, nil
}
