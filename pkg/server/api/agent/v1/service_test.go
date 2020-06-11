package agent_test

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/api/agent/v1"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	agentpb "github.com/spiffe/spire/proto/spire-next/api/server/agent/v1"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc"
)

type serviceTest struct { //nolint: unused,deadcode
	client  agentpb.AgentClient
	done    func()
	ds      *fakedatastore.DataStore
	logHook *test.Hook
}

func (c *serviceTest) Cleanup() {
	c.done()
}

func setupServiceTest(t *testing.T) *serviceTest { //nolint: unused,deadcode
	ds := fakedatastore.New()
	service := agent.New(agent.Config{
		Datastore: ds,
	})

	log, logHook := test.NewNullLogger()
	registerFn := func(s *grpc.Server) {
		agent.RegisterService(s, service)
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
	test.client = agentpb.NewAgentClient(conn)

	return test
}
