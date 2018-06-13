package registration

import (
	"context"
	"net/rpc"

	"github.com/golang/protobuf/ptypes/empty"
	go_plugin "github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/proto/common"
	"google.golang.org/grpc"
)

// Registration is the interface used by all non-catalog components.
type Registration interface {
	CreateEntry(context.Context, *common.RegistrationEntry) (*RegistrationEntryID, error)
	DeleteEntry(context.Context, *RegistrationEntryID) (*common.RegistrationEntry, error)
	FetchEntry(context.Context, *RegistrationEntryID) (*common.RegistrationEntry, error)
	FetchEntries(context.Context, *common.Empty) (*common.RegistrationEntries, error)
	UpdateEntry(context.Context, *UpdateEntryRequest) (*common.RegistrationEntry, error)
	ListByParentID(context.Context, *ParentID) (*common.RegistrationEntries, error)
	ListBySelector(context.Context, *common.Selector) (*common.RegistrationEntries, error)
	ListBySpiffeID(context.Context, *SpiffeID) (*common.RegistrationEntries, error)
	CreateFederatedBundle(context.Context, *CreateFederatedBundleRequest) (*common.Empty, error)
	ListFederatedBundles(context.Context, *common.Empty) (*ListFederatedBundlesReply, error)
	UpdateFederatedBundle(context.Context, *FederatedBundle) (*common.Empty, error)
	DeleteFederatedBundle(context.Context, *FederatedSpiffeID) (*common.Empty, error)
	CreateJoinToken(context.Context, *JoinToken) (*JoinToken, error)
	FetchBundle(context.Context, *common.Empty) (*Bundle, error)
}

// Registration is the interface implemented by plugin implementations
type RegistrationPlugin interface {
	CreateEntry(context.Context, *common.RegistrationEntry) (*RegistrationEntryID, error)
	DeleteEntry(context.Context, *RegistrationEntryID) (*common.RegistrationEntry, error)
	FetchEntry(context.Context, *RegistrationEntryID) (*common.RegistrationEntry, error)
	FetchEntries(context.Context, *common.Empty) (*common.RegistrationEntries, error)
	UpdateEntry(context.Context, *UpdateEntryRequest) (*common.RegistrationEntry, error)
	ListByParentID(context.Context, *ParentID) (*common.RegistrationEntries, error)
	ListBySelector(context.Context, *common.Selector) (*common.RegistrationEntries, error)
	ListBySpiffeID(context.Context, *SpiffeID) (*common.RegistrationEntries, error)
	CreateFederatedBundle(context.Context, *CreateFederatedBundleRequest) (*common.Empty, error)
	ListFederatedBundles(context.Context, *common.Empty) (*ListFederatedBundlesReply, error)
	UpdateFederatedBundle(context.Context, *FederatedBundle) (*common.Empty, error)
	DeleteFederatedBundle(context.Context, *FederatedSpiffeID) (*common.Empty, error)
	CreateJoinToken(context.Context, *JoinToken) (*JoinToken, error)
	FetchBundle(context.Context, *common.Empty) (*Bundle, error)
}

type RegistrationBuiltIn struct {
	plugin RegistrationPlugin
}

var _ Registration = (*RegistrationBuiltIn)(nil)

func NewRegistrationBuiltIn(plugin RegistrationPlugin) *RegistrationBuiltIn {
	return &RegistrationBuiltIn{
		plugin: plugin,
	}
}

func (b RegistrationBuiltIn) CreateEntry(ctx context.Context, req *common.RegistrationEntry) (*RegistrationEntryID, error) {
	return b.plugin.CreateEntry(ctx, req)
}

func (b RegistrationBuiltIn) DeleteEntry(ctx context.Context, req *RegistrationEntryID) (*common.RegistrationEntry, error) {
	return b.plugin.DeleteEntry(ctx, req)
}

func (b RegistrationBuiltIn) FetchEntry(ctx context.Context, req *RegistrationEntryID) (*common.RegistrationEntry, error) {
	return b.plugin.FetchEntry(ctx, req)
}

func (b RegistrationBuiltIn) FetchEntries(ctx context.Context, req *common.Empty) (*common.RegistrationEntries, error) {
	return b.plugin.FetchEntries(ctx, req)
}

func (b RegistrationBuiltIn) UpdateEntry(ctx context.Context, req *UpdateEntryRequest) (*common.RegistrationEntry, error) {
	return b.plugin.UpdateEntry(ctx, req)
}

func (b RegistrationBuiltIn) ListByParentID(ctx context.Context, req *ParentID) (*common.RegistrationEntries, error) {
	return b.plugin.ListByParentID(ctx, req)
}

func (b RegistrationBuiltIn) ListBySelector(ctx context.Context, req *common.Selector) (*common.RegistrationEntries, error) {
	return b.plugin.ListBySelector(ctx, req)
}

func (b RegistrationBuiltIn) ListBySpiffeID(ctx context.Context, req *SpiffeID) (*common.RegistrationEntries, error) {
	return b.plugin.ListBySpiffeID(ctx, req)
}

func (b RegistrationBuiltIn) CreateFederatedBundle(ctx context.Context, req *CreateFederatedBundleRequest) (*common.Empty, error) {
	return b.plugin.CreateFederatedBundle(ctx, req)
}

func (b RegistrationBuiltIn) ListFederatedBundles(ctx context.Context, req *common.Empty) (*ListFederatedBundlesReply, error) {
	return b.plugin.ListFederatedBundles(ctx, req)
}

func (b RegistrationBuiltIn) UpdateFederatedBundle(ctx context.Context, req *FederatedBundle) (*common.Empty, error) {
	return b.plugin.UpdateFederatedBundle(ctx, req)
}

func (b RegistrationBuiltIn) DeleteFederatedBundle(ctx context.Context, req *FederatedSpiffeID) (*common.Empty, error) {
	return b.plugin.DeleteFederatedBundle(ctx, req)
}

func (b RegistrationBuiltIn) CreateJoinToken(ctx context.Context, req *JoinToken) (*JoinToken, error) {
	return b.plugin.CreateJoinToken(ctx, req)
}

func (b RegistrationBuiltIn) FetchBundle(ctx context.Context, req *common.Empty) (*Bundle, error) {
	return b.plugin.FetchBundle(ctx, req)
}

var Handshake = go_plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "Registration",
	MagicCookieValue: "Registration",
}

type RegistrationGRPCPlugin struct {
	ServerImpl RegistrationServer
}

func (p RegistrationGRPCPlugin) Server(*go_plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p RegistrationGRPCPlugin) Client(b *go_plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p RegistrationGRPCPlugin) GRPCServer(s *grpc.Server) error {
	RegisterRegistrationServer(s, p.ServerImpl)
	return nil
}

func (p RegistrationGRPCPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &RegistrationGRPCClient{client: NewRegistrationClient(c)}, nil
}

type RegistrationGRPCServer struct {
	Plugin RegistrationPlugin
}

func (s *RegistrationGRPCServer) CreateEntry(ctx context.Context, req *common.RegistrationEntry) (*RegistrationEntryID, error) {
	return s.Plugin.CreateEntry(ctx, req)
}
func (s *RegistrationGRPCServer) DeleteEntry(ctx context.Context, req *RegistrationEntryID) (*common.RegistrationEntry, error) {
	return s.Plugin.DeleteEntry(ctx, req)
}
func (s *RegistrationGRPCServer) FetchEntry(ctx context.Context, req *RegistrationEntryID) (*common.RegistrationEntry, error) {
	return s.Plugin.FetchEntry(ctx, req)
}
func (s *RegistrationGRPCServer) FetchEntries(ctx context.Context, req *common.Empty) (*common.RegistrationEntries, error) {
	return s.Plugin.FetchEntries(ctx, req)
}
func (s *RegistrationGRPCServer) UpdateEntry(ctx context.Context, req *UpdateEntryRequest) (*common.RegistrationEntry, error) {
	return s.Plugin.UpdateEntry(ctx, req)
}
func (s *RegistrationGRPCServer) ListByParentID(ctx context.Context, req *ParentID) (*common.RegistrationEntries, error) {
	return s.Plugin.ListByParentID(ctx, req)
}
func (s *RegistrationGRPCServer) ListBySelector(ctx context.Context, req *common.Selector) (*common.RegistrationEntries, error) {
	return s.Plugin.ListBySelector(ctx, req)
}
func (s *RegistrationGRPCServer) ListBySpiffeID(ctx context.Context, req *SpiffeID) (*common.RegistrationEntries, error) {
	return s.Plugin.ListBySpiffeID(ctx, req)
}
func (s *RegistrationGRPCServer) CreateFederatedBundle(ctx context.Context, req *CreateFederatedBundleRequest) (*common.Empty, error) {
	return s.Plugin.CreateFederatedBundle(ctx, req)
}
func (s *RegistrationGRPCServer) ListFederatedBundles(ctx context.Context, req *common.Empty) (*ListFederatedBundlesReply, error) {
	return s.Plugin.ListFederatedBundles(ctx, req)
}
func (s *RegistrationGRPCServer) UpdateFederatedBundle(ctx context.Context, req *FederatedBundle) (*common.Empty, error) {
	return s.Plugin.UpdateFederatedBundle(ctx, req)
}
func (s *RegistrationGRPCServer) DeleteFederatedBundle(ctx context.Context, req *FederatedSpiffeID) (*common.Empty, error) {
	return s.Plugin.DeleteFederatedBundle(ctx, req)
}
func (s *RegistrationGRPCServer) CreateJoinToken(ctx context.Context, req *JoinToken) (*JoinToken, error) {
	return s.Plugin.CreateJoinToken(ctx, req)
}
func (s *RegistrationGRPCServer) FetchBundle(ctx context.Context, req *common.Empty) (*Bundle, error) {
	return s.Plugin.FetchBundle(ctx, req)
}

type RegistrationGRPCClient struct {
	client RegistrationClient
}

func (c *RegistrationGRPCClient) CreateEntry(ctx context.Context, req *common.RegistrationEntry) (*RegistrationEntryID, error) {
	return c.client.CreateEntry(ctx, req)
}
func (c *RegistrationGRPCClient) DeleteEntry(ctx context.Context, req *RegistrationEntryID) (*common.RegistrationEntry, error) {
	return c.client.DeleteEntry(ctx, req)
}
func (c *RegistrationGRPCClient) FetchEntry(ctx context.Context, req *RegistrationEntryID) (*common.RegistrationEntry, error) {
	return c.client.FetchEntry(ctx, req)
}
func (c *RegistrationGRPCClient) FetchEntries(ctx context.Context, req *common.Empty) (*common.RegistrationEntries, error) {
	return c.client.FetchEntries(ctx, req)
}
func (c *RegistrationGRPCClient) UpdateEntry(ctx context.Context, req *UpdateEntryRequest) (*common.RegistrationEntry, error) {
	return c.client.UpdateEntry(ctx, req)
}
func (c *RegistrationGRPCClient) ListByParentID(ctx context.Context, req *ParentID) (*common.RegistrationEntries, error) {
	return c.client.ListByParentID(ctx, req)
}
func (c *RegistrationGRPCClient) ListBySelector(ctx context.Context, req *common.Selector) (*common.RegistrationEntries, error) {
	return c.client.ListBySelector(ctx, req)
}
func (c *RegistrationGRPCClient) ListBySpiffeID(ctx context.Context, req *SpiffeID) (*common.RegistrationEntries, error) {
	return c.client.ListBySpiffeID(ctx, req)
}
func (c *RegistrationGRPCClient) CreateFederatedBundle(ctx context.Context, req *CreateFederatedBundleRequest) (*common.Empty, error) {
	return c.client.CreateFederatedBundle(ctx, req)
}
func (c *RegistrationGRPCClient) ListFederatedBundles(ctx context.Context, req *common.Empty) (*ListFederatedBundlesReply, error) {
	return c.client.ListFederatedBundles(ctx, req)
}
func (c *RegistrationGRPCClient) UpdateFederatedBundle(ctx context.Context, req *FederatedBundle) (*common.Empty, error) {
	return c.client.UpdateFederatedBundle(ctx, req)
}
func (c *RegistrationGRPCClient) DeleteFederatedBundle(ctx context.Context, req *FederatedSpiffeID) (*common.Empty, error) {
	return c.client.DeleteFederatedBundle(ctx, req)
}
func (c *RegistrationGRPCClient) CreateJoinToken(ctx context.Context, req *JoinToken) (*JoinToken, error) {
	return c.client.CreateJoinToken(ctx, req)
}
func (c *RegistrationGRPCClient) FetchBundle(ctx context.Context, req *common.Empty) (*Bundle, error) {
	return c.client.FetchBundle(ctx, req)
}
