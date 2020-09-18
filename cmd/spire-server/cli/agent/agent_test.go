package agent

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/mitchellh/cli"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/server/api/agent/v1"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	agentpb "github.com/spiffe/spire/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

var (
	td = spiffeid.RequireTrustDomainFromString("example.org")
)

type agentTest struct {
	client  agentpb.AgentClient
	ds      *fakedatastore.DataStore
	testEnv *common_cli.Env

	evictCmd,
	listCmd,
	showCmd cli.Command
}

func TestEvictHelp(t *testing.T) {
	test := setupTest(t)

	test.evictCmd.Help()
	require.Equal(t, `Usage of agent evict:
  -registrationUDSPath string
    	Registration API UDS path (default "/tmp/spire-registration.sock")
  -spiffeID string
    	The SPIFFE ID of the agent to evict (agent identity)
`, test.testEnv.Stderr.(*bytes.Buffer).String())
}

func TestEvict(t *testing.T) {
	for _, tt := range []struct {
		name               string
		args               []string
		expectedReturnCode int
		expectedStdout     string
		expectedStderr     string
		existentAgent      string
	}{
		{
			name:               "success",
			args:               []string{"-spiffeID", "spiffe://example.org/spire/agent/agent1"},
			expectedReturnCode: 0,
			existentAgent:      "spiffe://example.org/spire/agent/agent1",
			expectedStdout:     "Agent evicted successfully\n",
		},
		{
			name:               "agent does not exist",
			args:               []string{"-spiffeID", "spiffe://example.org/spire/agent/agent1"},
			expectedReturnCode: 1,
			existentAgent:      "spiffe://example.org/spire/agent/agent2",
			expectedStderr:     "rpc error: code = NotFound desc = agent not found\n",
		},
		{
			name:               "agent does not exist - no agents",
			args:               []string{"-spiffeID", "spiffe://example.org/spire/agent/agent1"},
			expectedReturnCode: 1,
			expectedStderr:     "rpc error: code = NotFound desc = agent not found\n",
		},
		{
			name:               "no spiffe id",
			expectedReturnCode: 1,
			existentAgent:      "spiffe://example.org/spire/agent/agent1",
			expectedStderr:     "a SPIFFE ID is required\n",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t)

			if tt.existentAgent != "" {
				test.createAgent(t, tt.existentAgent)
			}

			returnCode := test.evictCmd.Run(tt.args)
			require.Equal(t, tt.expectedStdout, test.testEnv.Stdout.(*bytes.Buffer).String())
			require.Equal(t, tt.expectedStderr, test.testEnv.Stderr.(*bytes.Buffer).String())
			require.Equal(t, tt.expectedReturnCode, returnCode)
		})
	}
}

func TestListHelp(t *testing.T) {
	test := setupTest(t)

	test.listCmd.Help()
	require.Equal(t, `Usage of agent list:
  -registrationUDSPath string
    	Registration API UDS path (default "/tmp/spire-registration.sock")
`, test.testEnv.Stderr.(*bytes.Buffer).String())
}

func TestList(t *testing.T) {
	for _, tt := range []struct {
		name               string
		expectedReturnCode int
		expectedStdout     string
		expectedStderr     string
		existentAgent      string
		dsError            error
	}{
		{
			name:               "1 agent",
			expectedReturnCode: 0,
			existentAgent:      "spiffe://example.org/spire/agent/agent1",
			expectedStdout:     "Found 1 attested agent:\n\nSPIFFE ID         : spiffe://example.org/spire/agent/agent1",
		},
		{
			name:               "no agents",
			expectedReturnCode: 0,
		},
		{
			name:               "datastore error",
			expectedReturnCode: 1,
			dsError:            errors.New("datastore error"),
			expectedStderr:     "rpc error: code = Internal desc = failed to list agents: datastore error\n",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t)
			if tt.existentAgent != "" {
				test.createAgent(t, tt.existentAgent)
			}

			test.ds.SetNextError(tt.dsError)
			returnCode := test.listCmd.Run([]string{})
			require.Contains(t, test.testEnv.Stdout.(*bytes.Buffer).String(), tt.expectedStdout)
			require.Equal(t, tt.expectedStderr, test.testEnv.Stderr.(*bytes.Buffer).String())
			require.Equal(t, tt.expectedReturnCode, returnCode)
		})
	}
}

func TestShowHelp(t *testing.T) {
	test := setupTest(t)

	test.showCmd.Help()
	require.Equal(t, `Usage of agent show:
  -registrationUDSPath string
    	Registration API UDS path (default "/tmp/spire-registration.sock")
  -spiffeID string
    	The SPIFFE ID of the agent to show (agent identity)
`, test.testEnv.Stderr.(*bytes.Buffer).String())
}

func TestShow(t *testing.T) {
	for _, tt := range []struct {
		name               string
		args               []string
		expectedReturnCode int
		expectedStdout     string
		expectedStderr     string
		existentAgent      string
		dsError            error
	}{
		{
			name:               "success",
			args:               []string{"-spiffeID", "spiffe://example.org/spire/agent/agent1"},
			expectedReturnCode: 0,
			existentAgent:      "spiffe://example.org/spire/agent/agent1",
			expectedStdout:     "Found an attested agent given its SPIFFE ID\n\nSPIFFE ID         : spiffe://example.org/spire/agent/agent1",
		},
		{
			name:               "spiffe id not found",
			args:               []string{"-spiffeID", "spiffe://example.org/spire/agent/agent2"},
			expectedReturnCode: 1,
			existentAgent:      "spiffe://example.org/spire/agent/agent1",
			expectedStderr:     "rpc error: code = NotFound desc = agent not found\n",
		},
		{
			name:               "no spiffe id",
			expectedReturnCode: 1,
			existentAgent:      "spiffe://example.org/spire/agent/agent1",
			expectedStderr:     "a SPIFFE ID is required\n",
		},
		{
			name:               "no agents - not found",
			expectedReturnCode: 1,
			args:               []string{"-spiffeID", "spiffe://example.org/spire/agent/agent1"},
			expectedStderr:     "rpc error: code = NotFound desc = agent not found\n",
		},
		{
			name:               "datastore error",
			args:               []string{"-spiffeID", "spiffe://example.org/spire/agent/agent1"},
			expectedReturnCode: 1,
			dsError:            errors.New("datastore error"),
			expectedStderr:     "rpc error: code = Internal desc = failed to fetch agent: datastore error\n",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t)
			if tt.existentAgent != "" {
				test.createAgent(t, tt.existentAgent)
			}

			test.ds.SetNextError(tt.dsError)
			returnCode := test.showCmd.Run(tt.args)
			require.Contains(t, test.testEnv.Stdout.(*bytes.Buffer).String(), tt.expectedStdout)
			require.Equal(t, tt.expectedStderr, test.testEnv.Stderr.(*bytes.Buffer).String())
			require.Equal(t, tt.expectedReturnCode, returnCode)
		})
	}
}

func setupTest(t *testing.T) *agentTest {
	ds := fakedatastore.New(t)

	service := agent.New(agent.Config{
		ServerCA:    fakeserverca.New(t, td.String(), &fakeserverca.Options{}),
		DataStore:   ds,
		TrustDomain: td,
		Clock:       clock.NewMock(t),
		Catalog:     fakeservercatalog.New(),
	})

	log, _ := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	registerFn := func(s *grpc.Server) {
		agent.RegisterService(s, service)
	}

	testEnv := &common_cli.Env{
		Stdin:  new(bytes.Buffer),
		Stdout: new(bytes.Buffer),
		Stderr: new(bytes.Buffer),
	}

	test := &agentTest{
		ds:      ds,
		testEnv: testEnv,
	}

	contextFn := func(ctx context.Context) context.Context {
		ctx = rpccontext.WithLogger(ctx, log)
		return ctx
	}

	conn, done := spiretest.NewAPIServer(t, registerFn, contextFn)
	clientMaker := func(string) (*util.Clients, error) {
		return &util.Clients{
			AgentClient: agentpb.NewAgentClient(conn),
		}, nil
	}

	test.client = agentpb.NewAgentClient(conn)
	test.evictCmd = newEvictCommand(testEnv, clientMaker)
	test.listCmd = newListCommand(testEnv, clientMaker)
	test.showCmd = newShowCommand(testEnv, clientMaker)

	t.Cleanup(func() {
		done()
	})

	return test
}

func (s *agentTest) createAgent(t *testing.T, spiffeID string) {
	_, err := s.ds.CreateAttestedNode(context.Background(), &datastore.CreateAttestedNodeRequest{
		Node: &common.AttestedNode{
			SpiffeId: spiffeID,
		},
	})
	require.NoError(t, err)
}
