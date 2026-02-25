package nodeattestor_test

import (
	"context"
	"errors"
	"testing"

	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestV1(t *testing.T) {
	var nilErr error
	ohnoErr := errors.New("ohno")
	agentID := "spiffe://example.org/spire/agent/test/foo"
	challenges := map[string][]string{
		"without-challenge": nil,
		"with-challenge":    {"one", "two", "three"},
	}
	selectors := []*common.Selector{{Type: "test", Value: "value"}}
	selectorValues := []string{"value"}
	resultWithoutSelectors := &nodeattestor.AttestResult{AgentID: agentID}
	resultWithSelectors := &nodeattestor.AttestResult{AgentID: agentID, Selectors: selectors}
	resultWithSelectorsAndCanReattest := &nodeattestor.AttestResult{AgentID: agentID, Selectors: selectors, CanReattest: true}

	for _, tt := range []struct {
		test           string
		plugin         *fakeV1Plugin
		payload        string
		responseErr    error
		expectAnyError bool
		expectCode     codes.Code
		expectMessage  string
		expectResult   *nodeattestor.AttestResult
	}{
		{
			test:          "payload cannot be empty",
			plugin:        &fakeV1Plugin{},
			expectCode:    codes.InvalidArgument,
			expectMessage: "payload cannot be empty",
		},
		{
			test:           "plugin closes stream immediately",
			plugin:         &fakeV1Plugin{preRecvError: &nilErr},
			payload:        "unused",
			expectAnyError: true,
		},
		{
			test:           "plugin fails immediately",
			plugin:         &fakeV1Plugin{preRecvError: &ohnoErr},
			payload:        "unused",
			expectAnyError: true,
		},
		{
			test:          "plugin closes stream after receiving data but before responding",
			plugin:        &fakeV1Plugin{postRecvError: &nilErr},
			payload:       "unused",
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(test): plugin closed stream unexpectedly",
		},
		{
			test:          "plugin fails after receiving data but before responding",
			plugin:        &fakeV1Plugin{postRecvError: &ohnoErr},
			payload:       "unused",
			expectCode:    codes.Unknown,
			expectMessage: "nodeattestor(test): ohno",
		},
		{
			test:          "attestation fails",
			plugin:        &fakeV1Plugin{},
			payload:       "bad",
			expectCode:    codes.InvalidArgument,
			expectMessage: "nodeattestor(test): attestation failed by test",
		},
		{
			test:          "challenge response",
			plugin:        &fakeV1Plugin{},
			payload:       "unused",
			expectCode:    codes.InvalidArgument,
			expectMessage: "nodeattestor(test): attestation failed by test",
		},
		{
			test:          "attestation succeeds with no challenges or selectors",
			plugin:        &fakeV1Plugin{challenges: challenges, agentID: agentID},
			payload:       "without-challenge",
			expectCode:    codes.OK,
			expectMessage: "",
			expectResult:  resultWithoutSelectors,
		},
		{
			test:          "attestation succeeds with challenges and selectors",
			plugin:        &fakeV1Plugin{challenges: challenges, agentID: agentID, selectorValues: selectorValues},
			payload:       "with-challenge",
			expectCode:    codes.OK,
			expectMessage: "",
			expectResult:  resultWithSelectors,
		},
		{
			test:       "attestation fails if plugin response missing agent ID",
			plugin:     &fakeV1Plugin{challenges: challenges},
			payload:    "with-challenge",
			expectCode: codes.Internal,
			// errors returned by the callback are returned verbatim
			expectMessage: "nodeattestor(test): plugin response missing agent ID",
		},
		{
			test:        "attestation fails if challenge response fails",
			plugin:      &fakeV1Plugin{challenges: challenges},
			payload:     "with-challenge",
			responseErr: errors.New("response error"),
			expectCode:  codes.Unknown,
			// errors returned by the callback are returned verbatim
			expectMessage: "response error",
		},
		{
			test:          "CanReattest flag is passed through",
			plugin:        &fakeV1Plugin{challenges: challenges, agentID: agentID, selectorValues: selectorValues, canReattest: true},
			payload:       "without-challenge",
			expectCode:    codes.OK,
			expectMessage: "",
			expectResult:  resultWithSelectorsAndCanReattest,
		},
	} {
		t.Run(tt.test, func(t *testing.T) {
			nodeattestor := loadV1Plugin(t, tt.plugin)
			result, err := nodeattestor.Attest(context.Background(), []byte(tt.payload),
				func(ctx context.Context, challenge []byte) ([]byte, error) {
					// echo the challenge back
					return challenge, tt.responseErr
				},
			)
			switch {
			case tt.expectAnyError:
				require.Error(t, err)
				require.Contains(t, err.Error(), "nodeattestor(test): ")
				return
			case tt.expectCode != codes.OK:
				spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMessage)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectResult.AgentID, result.AgentID)
			assert.Equal(t, tt.expectResult.CanReattest, result.CanReattest)
			spiretest.AssertProtoListEqual(t, tt.expectResult.Selectors, result.Selectors)
		})
	}
}

type ForwardedHostV1Plugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer
	ExpectedHost string
}

func (plugin *ForwardedHostV1Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	xForwardedHost := metadata.ValueFromIncomingContext(stream.Context(), nodeattestor.XForwardedHostKey)
	if len(xForwardedHost) == 0 || xForwardedHost[0] != plugin.ExpectedHost {
		return errors.New("expected forwarded host in context metadata")
	}
	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId: "spiffe://example.org/spire/agent/test/foo",
			},
		},
	})
}

func TestHostForwarding(t *testing.T) {
	server := nodeattestorv1.NodeAttestorPluginServer(&ForwardedHostV1Plugin{ExpectedHost: "spire-server-xyz.spiffe.io"})
	nodeattestor := new(nodeattestor.V1)
	plugintest.Load(t, catalog.MakeBuiltIn("test", server), nodeattestor)

	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.New(map[string]string{":authority": "spire-server-xyz.spiffe.io:8081"}),
	)
	result, err := nodeattestor.Attest(ctx, []byte("unused"), func(ctx context.Context, challenge []byte) ([]byte, error) {
		return challenge, nil
	})

	require.NoError(t, err)
	require.NotNil(t, result)
}

func loadV1Plugin(t *testing.T, plugin *fakeV1Plugin) nodeattestor.NodeAttestor {
	server := nodeattestorv1.NodeAttestorPluginServer(plugin)

	na := new(nodeattestor.V1)
	plugintest.Load(t, catalog.MakeBuiltIn("test", server), na)
	return na
}

type fakeV1Plugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer

	preRecvError   *error
	postRecvError  *error
	challenges     map[string][]string
	agentID        string
	selectorValues []string
	canReattest    bool
}

func (plugin *fakeV1Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	if plugin.preRecvError != nil {
		return *plugin.preRecvError
	}

	req, err := stream.Recv()
	if err != nil {
		return err
	}

	if plugin.postRecvError != nil {
		return *plugin.postRecvError
	}

	payload := req.GetPayload()
	if payload == nil {
		return errors.New("shim passed no payload")
	}

	challenges, ok := plugin.challenges[string(payload)]
	if !ok {
		return status.Error(codes.InvalidArgument, "attestation failed by test")
	}

	for _, challenge := range challenges {
		if err := stream.Send(&nodeattestorv1.AttestResponse{
			Response: &nodeattestorv1.AttestResponse_Challenge{
				Challenge: []byte(challenge),
			},
		}); err != nil {
			return err
		}

		req, err := stream.Recv()
		if err != nil {
			return err
		}
		challengeResponse := req.GetChallengeResponse()
		if challengeResponse == nil {
			return errors.New("shim passed no challenge response")
		}
		if string(challengeResponse) != challenge {
			return status.Errorf(codes.InvalidArgument, "expected response %q; got %q", challenge, string(challengeResponse))
		}
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       plugin.agentID,
				SelectorValues: plugin.selectorValues,
				CanReattest:    plugin.canReattest,
			},
		},
	})
}
