package fakeregistrationclient

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/agent/auth"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	ep_registration "github.com/spiffe/spire/pkg/server/endpoints/registration"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Client struct {
	server      *grpc.Server
	nowFn       func() time.Time
	trustDomain string

	registration.RegistrationClient
}

func New(t *testing.T, trustDomain string, ds datastore.DataStore, nowFn func() time.Time) *Client {
	if ds == nil {
		ds = fakedatastore.New()
	}
	if nowFn == nil {
		nowFn = time.Now
	}

	trustDomainURL, err := idutil.ParseSpiffeID(trustDomain, idutil.AllowAnyTrustDomain())
	require.NoError(t, err)

	c := &Client{
		server:      grpc.NewServer(grpc.Creds(fakeTransportCreds{})),
		nowFn:       nowFn,
		trustDomain: trustDomain,
	}

	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	catalog := fakeservercatalog.New()
	catalog.SetDataStores(ds)
	server := &ep_registration.Handler{
		Catalog:     catalog,
		Metrics:     telemetry.Blackhole{},
		TrustDomain: *trustDomainURL,
	}
	registration.RegisterRegistrationServer(c.server, server)

	conn, err := grpc.Dial(listener.Addr().String(), grpc.WithInsecure())
	require.NoError(t, err)

	c.RegistrationClient = registration.NewRegistrationClient(conn)

	go c.server.Serve(listener)

	return c
}

func (c *Client) Close() {
	c.server.Stop()
}

// fakeTransportCreds is simply used to supply "unix domain socket" auth info
// to the registration handler.
type fakeTransportCreds struct{}

func (fakeTransportCreds) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, nil, nil
}

func (fakeTransportCreds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, auth.CallerInfo{}, nil
}

func (fakeTransportCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{}
}

func (fakeTransportCreds) Clone() credentials.TransportCredentials {
	return fakeTransportCreds{}
}

func (fakeTransportCreds) OverrideServerName(string) error {
	return nil
}
