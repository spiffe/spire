// Provides interfaces and adapters for the IdentityProvider service
//
// Generated code. Do not modify by hand.
package identityproviderv0

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc"
)

const (
	Type = "IdentityProvider"
)

// IdentityProvider is the client interface for the service type IdentityProvider interface.
type IdentityProvider interface {
	FetchX509Identity(context.Context, *FetchX509IdentityRequest) (*FetchX509IdentityResponse, error)
}

// HostServiceServer returns a catalog HostServiceServer implementation for the IdentityProvider plugin.
func HostServiceServer(server IdentityProviderServer) catalog.HostServiceServer {
	return &hostServiceServer{
		server: server,
	}
}

type hostServiceServer struct {
	server IdentityProviderServer
}

func (s hostServiceServer) HostServiceType() string {
	return Type
}

func (s hostServiceServer) RegisterHostServiceServer(server *grpc.Server) {
	RegisterIdentityProviderServer(server, s.server)
}

// HostServiceServer returns a catalog HostServiceServer implementation for the IdentityProvider plugin.
func HostServiceClient(client *IdentityProvider) catalog.HostServiceClient {
	return &hostServiceClient{
		client: client,
	}
}

type hostServiceClient struct {
	client *IdentityProvider
}

func (c *hostServiceClient) HostServiceType() string {
	return Type
}

func (c *hostServiceClient) InitHostServiceClient(conn grpc.ClientConnInterface) {
	*c.client = AdaptHostServiceClient(NewIdentityProviderClient(conn))
}

func AdaptHostServiceClient(client IdentityProviderClient) IdentityProvider {
	return hostServiceClientAdapter{client: client}
}

type hostServiceClientAdapter struct {
	client IdentityProviderClient
}

func (a hostServiceClientAdapter) FetchX509Identity(ctx context.Context, in *FetchX509IdentityRequest) (*FetchX509IdentityResponse, error) {
	return a.client.FetchX509Identity(ctx, in)
}
