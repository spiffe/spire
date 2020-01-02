// Provides interfaces and adapters for the IdentityProvider service
//
// Generated code. Do not modify by hand.
package hostservices

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/server/hostservices"
	"google.golang.org/grpc"
)

type FetchX509IdentityRequest = hostservices.FetchX509IdentityRequest                       //nolint: golint
type FetchX509IdentityResponse = hostservices.FetchX509IdentityResponse                     //nolint: golint
type IdentityProviderClient = hostservices.IdentityProviderClient                           //nolint: golint
type IdentityProviderServer = hostservices.IdentityProviderServer                           //nolint: golint
type UnimplementedIdentityProviderServer = hostservices.UnimplementedIdentityProviderServer //nolint: golint
type X509Identity = hostservices.X509Identity                                               //nolint: golint

const (
	IdentityProviderType = "IdentityProvider"
)

// IdentityProvider is the client interface for the service type IdentityProvider interface.
type IdentityProvider interface {
	FetchX509Identity(context.Context, *FetchX509IdentityRequest) (*FetchX509IdentityResponse, error)
}

// IdentityProviderHostServiceServer returns a catalog HostServiceServer implementation for the IdentityProvider plugin.
func IdentityProviderHostServiceServer(server IdentityProviderServer) catalog.HostServiceServer {
	return &identityProviderHostServiceServer{
		server: server,
	}
}

type identityProviderHostServiceServer struct {
	server IdentityProviderServer
}

func (s identityProviderHostServiceServer) HostServiceType() string {
	return IdentityProviderType
}

func (s identityProviderHostServiceServer) RegisterHostServiceServer(server *grpc.Server) {
	hostservices.RegisterIdentityProviderServer(server, s.server)
}

// IdentityProviderHostServiceServer returns a catalog HostServiceServer implementation for the IdentityProvider plugin.
func IdentityProviderHostServiceClient(client *IdentityProvider) catalog.HostServiceClient {
	return &identityProviderHostServiceClient{
		client: client,
	}
}

type identityProviderHostServiceClient struct {
	client *IdentityProvider
}

func (c *identityProviderHostServiceClient) HostServiceType() string {
	return IdentityProviderType
}

func (c *identityProviderHostServiceClient) InitHostServiceClient(conn *grpc.ClientConn) {
	*c.client = AdaptIdentityProviderHostServiceClient(hostservices.NewIdentityProviderClient(conn))
}

func AdaptIdentityProviderHostServiceClient(client IdentityProviderClient) IdentityProvider {
	return identityProviderHostServiceClientAdapter{client: client}
}

type identityProviderHostServiceClientAdapter struct {
	client IdentityProviderClient
}

func (a identityProviderHostServiceClientAdapter) FetchX509Identity(ctx context.Context, in *FetchX509IdentityRequest) (*FetchX509IdentityResponse, error) {
	return a.client.FetchX509Identity(ctx, in)
}
