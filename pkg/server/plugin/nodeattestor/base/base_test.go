package base_test

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/base"
	"github.com/spiffe/spire/test/fakes/fakeagentstore"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestBaseRequiresAgentStoreHostService(t *testing.T) {
	var err error
	plugintest.Load(t, fakeBuiltIn(), nil, plugintest.CaptureLoadError(&err))
	spiretest.RequireGRPCStatus(t, err, codes.Internal, "required AgentStore host service not available")
}

func TestBaseAssessTOFU(t *testing.T) {
	const unattestedID = "spiffe://domain.test/spire/agent/unattested"
	const attestedID = "spiffe://domain.test/spire/agent/attested"
	const errorID = "spiffe://domain.test/spire/agent/error"

	log, hook := test.NewNullLogger()

	agentStore := fakeagentstore.New()
	agentStore.SetAgentInfo(&agentstorev1.AgentInfo{AgentId: attestedID})
	agentStore.SetAgentErr(errorID, status.Error(codes.Internal, "ohno"))
	na := new(nodeattestor.V1)
	plugintest.Load(t, fakeBuiltIn(), na,
		plugintest.HostServices(agentstorev1.AgentStoreServiceServer(agentStore)),
		plugintest.Log(log),
	)

	failOnChallenge := func(context.Context, []byte) ([]byte, error) {
		return nil, errors.New("unexpected challenge")
	}

	t.Run("with unattested agent", func(t *testing.T) {
		hook.Reset()
		result, err := na.Attest(context.Background(), []byte(unattestedID), failOnChallenge)
		require.NoError(t, err)
		require.Equal(t, &nodeattestor.AttestResult{
			AgentID: unattestedID,
		}, result)
		spiretest.AssertLogs(t, hook.AllEntries(), nil)
	})

	t.Run("with already attested agent", func(t *testing.T) {
		hook.Reset()
		result, err := na.Attest(context.Background(), []byte(attestedID), failOnChallenge)
		spiretest.RequireGRPCStatus(t, err, codes.PermissionDenied, "nodeattestor(fake): attestation data has already been used to attest an agent")
		require.Nil(t, result)
		spiretest.AssertLogs(t, hook.AllEntries(), []spiretest.LogEntry{
			{
				Level:   logrus.ErrorLevel,
				Message: "Attestation data has already been used to attest an agent",
				Data: logrus.Fields{
					"spiffe_id": "spiffe://domain.test/spire/agent/attested",
				},
			},
		})
	})

	t.Run("fails to query agent store", func(t *testing.T) {
		hook.Reset()
		result, err := na.Attest(context.Background(), []byte(errorID), failOnChallenge)
		spiretest.RequireGRPCStatus(t, err, codes.Internal, "nodeattestor(fake): unable to get agent info: ohno")
		require.Nil(t, result)
	})
}

func fakeBuiltIn() catalog.BuiltIn {
	return catalog.BuiltIn{
		Name:   "fake",
		Plugin: nodeattestorv1.NodeAttestorPluginServer(&fakePlugin{}),
	}
}

type fakePlugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer
	base.Base
	log hclog.Logger
}

func (p *fakePlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *fakePlugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	spiffeID := string(req.GetPayload())

	if err := p.AssessTOFU(stream.Context(), spiffeID, p.log); err != nil {
		return err
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId: spiffeID,
			},
		},
	})
}
