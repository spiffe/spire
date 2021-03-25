package nodeattestor_test

import (
	"context"
	"errors"
	"testing"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common"
	nodeattestorv0 "github.com/spiffe/spire/proto/spire/server/nodeattestor/v0"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gotest.tools/assert"
)

func TestV0(t *testing.T) {
	var nilErr error
	ohnoErr := errors.New("ohno")
	agentID := "spiffe://example.org/spire/agent/test/foo"
	challenges := map[string][]string{
		"without-challenge": nil,
		"with-challenge":    {"one", "two", "three"},
	}
	selectors := []*common.Selector{{Type: "type", Value: "value"}}
	resultWithoutSelectors := &nodeattestor.AttestResult{AgentID: agentID}
	resultWithSelectors := &nodeattestor.AttestResult{AgentID: agentID, Selectors: selectors}

	for _, tt := range []struct {
		test          string
		plugin        *fakeV0Plugin
		payload       string
		responseErr   error
		expectCode    codes.Code
		expectMessage string
		expectResult  *nodeattestor.AttestResult
	}{
		{
			test:          "plugin closes stream immediately",
			plugin:        &fakeV0Plugin{preRecvError: &nilErr},
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(test): plugin closed stream unexpectedly",
		},
		{
			test:          "plugin fails immediately",
			plugin:        &fakeV0Plugin{preRecvError: &ohnoErr},
			expectCode:    codes.Unknown,
			expectMessage: "nodeattestor(test): ohno",
		},
		{
			test:          "plugin closes stream after receiving data but before responding",
			plugin:        &fakeV0Plugin{postRecvError: &nilErr},
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(test): plugin closed stream unexpectedly",
		},
		{
			test:          "plugin fails after receiving data but before responding",
			plugin:        &fakeV0Plugin{postRecvError: &ohnoErr},
			expectCode:    codes.Unknown,
			expectMessage: "nodeattestor(test): ohno",
		},
		{
			test:          "attestation fails",
			plugin:        &fakeV0Plugin{},
			payload:       "bad",
			expectCode:    codes.InvalidArgument,
			expectMessage: "nodeattestor(test): attestation failed by test",
		},
		{
			test:          "challenge response",
			plugin:        &fakeV0Plugin{},
			expectCode:    codes.InvalidArgument,
			expectMessage: "nodeattestor(test): attestation failed by test",
		},
		{
			test:          "attestation succeeds with no challenges or selectors",
			plugin:        &fakeV0Plugin{challenges: challenges, agentID: agentID},
			payload:       "without-challenge",
			expectCode:    codes.OK,
			expectMessage: "",
			expectResult:  resultWithoutSelectors,
		},
		{
			test:          "attestation succeeds with challenges and selectors",
			plugin:        &fakeV0Plugin{challenges: challenges, agentID: agentID, selectors: selectors},
			payload:       "with-challenge",
			expectCode:    codes.OK,
			expectMessage: "",
			expectResult:  resultWithSelectors,
		},
		{
			test:       "attestation fails if plugin response missing agent ID",
			plugin:     &fakeV0Plugin{challenges: challenges},
			payload:    "with-challenge",
			expectCode: codes.Internal,
			// errors returned by the callback are returned verbatim
			expectMessage: "nodeattestor(test): plugin response missing agent ID",
		},
		{
			test:        "attestation fails if challenge response fails",
			plugin:      &fakeV0Plugin{challenges: challenges},
			payload:     "with-challenge",
			responseErr: errors.New("response error"),
			expectCode:  codes.Unknown,
			// errors returned by the callback are returned verbatim
			expectMessage: "response error",
		},
	} {
		tt := tt
		t.Run(tt.test, func(t *testing.T) {
			nodeattestor := loadV0Plugin(t, tt.plugin)
			result, err := nodeattestor.Attest(context.Background(), []byte(tt.payload),
				func(ctx context.Context, challenge []byte) ([]byte, error) {
					// echo the challenge back
					return challenge, tt.responseErr
				},
			)
			if tt.expectCode != codes.OK {
				spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMessage)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectResult.AgentID, result.AgentID)
			spiretest.AssertProtoListEqual(t, tt.expectResult.Selectors, result.Selectors)
		})
	}
}

func loadV0Plugin(t *testing.T, plugin *fakeV0Plugin) nodeattestor.NodeAttestor {
	server := nodeattestorv0.PluginServer(plugin)

	var na nodeattestor.V0
	spiretest.LoadPlugin(t, catalog.MakePlugin("test", server), &na)
	return na
}

type fakeV0Plugin struct {
	nodeattestorv0.UnimplementedNodeAttestorServer

	preRecvError  *error
	postRecvError *error
	challenges    map[string][]string
	agentID       string
	selectors     []*common.Selector
}

func (plugin *fakeV0Plugin) Attest(stream nodeattestorv0.NodeAttestor_AttestServer) error {
	if plugin.preRecvError != nil {
		return *plugin.preRecvError
	}

	resp, err := stream.Recv()
	if err != nil {
		return err
	}

	if plugin.postRecvError != nil {
		return *plugin.postRecvError
	}

	switch {
	case resp.AttestationData == nil:
		return errors.New("shim passed no attestation data")
	case resp.AttestationData.Type != "test":
		return errors.New("shim passed the wrong attestation type")
	}

	challenges, ok := plugin.challenges[string(resp.AttestationData.Data)]
	if !ok {
		return status.Error(codes.InvalidArgument, "attestation failed by test")
	}

	for _, challenge := range challenges {
		if err := stream.Send(&nodeattestorv0.AttestResponse{
			Challenge: []byte(challenge),
		}); err != nil {
			return err
		}

		resp, err = stream.Recv()
		if err != nil {
			return err
		}
		if string(resp.Response) != challenge {
			return status.Errorf(codes.InvalidArgument, "expected response %q; got %q", challenge, string(resp.Response))
		}
	}

	return stream.Send(&nodeattestorv0.AttestResponse{
		AgentId:   plugin.agentID,
		Selectors: plugin.selectors,
	})
}
