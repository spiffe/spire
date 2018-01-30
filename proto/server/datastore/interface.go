package datastore

import (
	"net/rpc"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/proto/common"

	"google.golang.org/grpc"

	spi "github.com/spiffe/spire/proto/common/plugin"
)

const TimeFormat = time.RFC1123Z

// Handshake is a common handshake that is shared between noderesolution and host.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "DataStore",
	MagicCookieValue: "DataStore",
}

type DataStore interface {
	CreateBundle(request *Bundle) (*Bundle, error)
	UpdateBundle(request *Bundle) (*Bundle, error)
	AppendBundle(request *Bundle) (*Bundle, error)
	DeleteBundle(request *Bundle) (*Bundle, error)
	FetchBundle(request *Bundle) (*Bundle, error)
	ListBundles(request *common.Empty) (*Bundles, error)

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
	FetchRegistrationEntries(request *common.Empty) (*FetchRegistrationEntriesResponse, error)
	UpdateRegistrationEntry(request *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error)
	DeleteRegistrationEntry(request *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error)

	ListParentIDEntries(request *ListParentIDEntriesRequest) (*ListParentIDEntriesResponse, error)
	ListSelectorEntries(request *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error)
	ListMatchingEntries(request *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error)
	ListSpiffeEntries(request *ListSpiffeEntriesRequest) (*ListSpiffeEntriesResponse, error)

	RegisterToken(request *JoinToken) (*common.Empty, error)
	FetchToken(request *JoinToken) (*JoinToken, error)
	DeleteToken(request *JoinToken) (*common.Empty, error)
	PruneTokens(request *JoinToken) (*common.Empty, error)

	Configure(request *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
	GetPluginInfo(request *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error)
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
