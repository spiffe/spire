package entry_test

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/api/entry/v1"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	entrypb "github.com/spiffe/spire/proto/spire-next/api/server/entry/v1"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc"
)

type serviceTest struct { //nolint: unused,deadcode
	client  entrypb.EntryClient
	done    func()
	ds      *fakedatastore.DataStore
	logHook *test.Hook
}

func (c *serviceTest) Cleanup() {
	c.done()
}

func setupServiceTest(t *testing.T) *serviceTest { //nolint: unused,deadcode
	ds := fakedatastore.New()
	service := entry.New(entry.Config{
		Datastore: ds,
	})

	log, logHook := test.NewNullLogger()
	registerFn := func(s *grpc.Server) {
		entry.RegisterService(s, service)
	}

	test := &serviceTest{
		ds:      ds,
		logHook: logHook,
	}

	contextFn := func(ctx context.Context) context.Context {
		ctx = rpccontext.WithLogger(ctx, log)
		return ctx
	}

	conn, done := spiretest.NewAPIServer(t, registerFn, contextFn)
	test.done = done
	test.client = entrypb.NewEntryClient(conn)

	return test
}
