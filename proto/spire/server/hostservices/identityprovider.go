// Provides interfaces and adapters for the IdentityProvider service
//
// Generated code. Do not modify by hand.
package hostservices

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc"
)

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
	RegisterIdentityProviderServer(server, s.server)
}

// IdentityProviderHostServiceServer returns a catalog HostServiceServer implementation for the IdentityProvider plugin.
func IdentityProviderHostServiceClient(client *IdentityProviderClient) catalog.HostServiceClient {
	return &identityProviderHostServiceClient{
		client: client,
	}
}

type identityProviderHostServiceClient struct {
	client *IdentityProviderClient
}

func (c *identityProviderHostServiceClient) HostServiceType() string {
	return IdentityProviderType
}

func (c *identityProviderHostServiceClient) InitHostServiceClient(conn *grpc.ClientConn) {
	*c.client = NewIdentityProviderClient(conn)
}
