package datastore

import (
	"net/rpc"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/proto/common"
	"golang.org/x/net/context"

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
	CreateBundle(ctx context.Context, request *Bundle) (*Bundle, error)
	UpdateBundle(ctx context.Context, request *Bundle) (*Bundle, error)
	AppendBundle(ctx context.Context, request *Bundle) (*Bundle, error)
	DeleteBundle(ctx context.Context, request *Bundle) (*Bundle, error)
	FetchBundle(ctx context.Context, request *Bundle) (*Bundle, error)
	ListBundles(ctx context.Context, request *common.Empty) (*Bundles, error)

	CreateAttestedNodeEntry(ctx context.Context, request *CreateAttestedNodeEntryRequest) (*CreateAttestedNodeEntryResponse, error)
	FetchAttestedNodeEntry(ctx context.Context, request *FetchAttestedNodeEntryRequest) (*FetchAttestedNodeEntryResponse, error)
	FetchStaleNodeEntries(ctx context.Context, request *FetchStaleNodeEntriesRequest) (*FetchStaleNodeEntriesResponse, error)
	UpdateAttestedNodeEntry(ctx context.Context, request *UpdateAttestedNodeEntryRequest) (*UpdateAttestedNodeEntryResponse, error)
	DeleteAttestedNodeEntry(ctx context.Context, request *DeleteAttestedNodeEntryRequest) (*DeleteAttestedNodeEntryResponse, error)

	CreateNodeResolverMapEntry(ctx context.Context, request *CreateNodeResolverMapEntryRequest) (*CreateNodeResolverMapEntryResponse, error)
	FetchNodeResolverMapEntry(ctx context.Context, request *FetchNodeResolverMapEntryRequest) (*FetchNodeResolverMapEntryResponse, error)
	DeleteNodeResolverMapEntry(ctx context.Context, request *DeleteNodeResolverMapEntryRequest) (*DeleteNodeResolverMapEntryResponse, error)
	RectifyNodeResolverMapEntries(ctx context.Context, request *RectifyNodeResolverMapEntriesRequest) (*RectifyNodeResolverMapEntriesResponse, error)

	CreateRegistrationEntry(ctx context.Context, request *CreateRegistrationEntryRequest) (*CreateRegistrationEntryResponse, error)
	FetchRegistrationEntry(ctx context.Context, request *FetchRegistrationEntryRequest) (*FetchRegistrationEntryResponse, error)
	FetchRegistrationEntries(ctx context.Context, request *common.Empty) (*FetchRegistrationEntriesResponse, error)
	UpdateRegistrationEntry(ctx context.Context, request *UpdateRegistrationEntryRequest) (*UpdateRegistrationEntryResponse, error)
	DeleteRegistrationEntry(ctx context.Context, request *DeleteRegistrationEntryRequest) (*DeleteRegistrationEntryResponse, error)

	ListParentIDEntries(ctx context.Context, request *ListParentIDEntriesRequest) (*ListParentIDEntriesResponse, error)
	ListSelectorEntries(ctx context.Context, request *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error)
	ListMatchingEntries(ctx context.Context, request *ListSelectorEntriesRequest) (*ListSelectorEntriesResponse, error)
	ListSpiffeEntries(ctx context.Context, request *ListSpiffeEntriesRequest) (*ListSpiffeEntriesResponse, error)

	RegisterToken(ctx context.Context, request *JoinToken) (*common.Empty, error)
	FetchToken(ctx context.Context, request *JoinToken) (*JoinToken, error)
	DeleteToken(ctx context.Context, request *JoinToken) (*common.Empty, error)
	PruneTokens(ctx context.Context, request *JoinToken) (*common.Empty, error)

	Configure(ctx context.Context, request *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
	GetPluginInfo(ctx context.Context, request *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error)
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
	RegisterDataStoreServer(s, p.DataStoreImpl)
	return nil
}

func (p DataStorePlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewDataStoreClient(c)}, nil
}
