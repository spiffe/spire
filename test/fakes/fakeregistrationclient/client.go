package fakeregistrationclient

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/common/telemetry"
	ep_registration "github.com/spiffe/spire/pkg/server/endpoints/registration"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Client struct {
	server      *grpc.Server
	nowFn       func() time.Time
	trustDomain spiffeid.TrustDomain

	registration.RegistrationClient
}

func New(t *testing.T, trustDomain spiffeid.TrustDomain, ds datastore.DataStore, nowFn func() time.Time) *Client {
	if ds == nil {
		ds = fakedatastore.New(t)
	}
	if nowFn == nil {
		nowFn = time.Now
	}

	c := &Client{
		server:      grpc.NewServer(grpc.Creds(fakeTransportCreds{})),
		nowFn:       nowFn,
		trustDomain: trustDomain,
	}

	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	catalog := fakeservercatalog.New()
	catalog.SetDataStore(ds)
	logger, _ := test.NewNullLogger()
	server := &ep_registration.Handler{
		Catalog:     catalog,
		Log:         logger,
		Metrics:     telemetry.Blackhole{},
		TrustDomain: trustDomain,
	}
	registration.RegisterRegistrationServer(c.server, server)

	conn, err := grpc.Dial(listener.Addr().String(), grpc.WithInsecure())
	require.NoError(t, err)

	c.RegistrationClient = registration.NewRegistrationClient(conn)

	go func() { _ = c.server.Serve(listener) }()

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
	return conn, peertracker.AuthInfo{}, nil
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
