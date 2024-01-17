package fakeentryclient

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/pkg/server/api/audit"
	"github.com/spiffe/spire/pkg/server/api/entry/v1"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/test/spiretest"

	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Client struct {
	server      *grpc.Server
	nowFn       func() time.Time
	trustDomain spiffeid.TrustDomain
	done        func()

	entryv1.EntryClient
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

	catalog := fakeservercatalog.New()
	catalog.SetDataStore(ds)

	server := entry.New(entry.Config{
		TrustDomain: trustDomain,
		DataStore:   ds,
		//EntryFetcher: authorizedEntryFetcherWithCache,
	})

	log, _ := test.NewNullLogger()
	registerFn := func(s *grpc.Server) {
		entryv1.RegisterEntryServer(s, server)
	}

	contextFn := func(ctx context.Context) context.Context {
		ctx = rpccontext.WithLogger(ctx, log)
		ctx = rpccontext.WithAdminCaller(ctx)
		ctx = rpccontext.WithAuditLog(ctx, audit.New(log))
		return ctx
	}

	conn, done := spiretest.NewAPIServer(t, registerFn, contextFn)

	c.done = done
	c.EntryClient = entryv1.NewEntryClient(conn)

	return c
}

func (c *Client) Close() {
	c.done()
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
