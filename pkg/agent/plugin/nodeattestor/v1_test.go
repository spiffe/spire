package nodeattestor_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	nodeattestortest "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/test"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestV1(t *testing.T) {
	streamBuilder := nodeattestortest.ServerStream("test")
	payload := []byte("payload")
	challenge := []byte("challenge")
	challengeResponse := []byte("challengeResponse")

	for _, tt := range []struct {
		test          string
		pluginImpl    *fakeV1Plugin
		streamImpl    nodeattestor.ServerStream
		expectCode    codes.Code
		expectMessage string
	}{
		{
			test:          "plugin closes stream without returning attestation data",
			pluginImpl:    &fakeV1Plugin{closeStream: true},
			streamImpl:    streamBuilder.Build(),
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(test): plugin closed stream before returning attestation data",
		},
		{
			test:          "plugin fails fetching payload",
			pluginImpl:    &fakeV1Plugin{payloadErr: errors.New("ohno")},
			streamImpl:    streamBuilder.Build(),
			expectCode:    codes.Unknown,
			expectMessage: "nodeattestor(test): ohno",
		},
		{
			test:          "plugin does not return attestation data",
			pluginImpl:    &fakeV1Plugin{},
			streamImpl:    streamBuilder.Build(),
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(test): plugin response missing attestation payload",
		},
		{
			test:          "plugin returns empty payload",
			pluginImpl:    &fakeV1Plugin{payload: []byte("")},
			streamImpl:    streamBuilder.Build(),
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(test): plugin response missing attestation payload",
		},
		{
			test:          "server stream fails sending attestation data",
			pluginImpl:    &fakeV1Plugin{payload: payload},
			streamImpl:    streamBuilder.FailAndBuild(errors.New("ohno")),
			expectCode:    codes.Unknown,
			expectMessage: "ohno",
		},
		{
			test:          "server stream issues no challenge",
			pluginImpl:    &fakeV1Plugin{payload: payload},
			streamImpl:    streamBuilder.ExpectAndBuild(payload),
			expectCode:    codes.OK,
			expectMessage: "",
		},
		{
			test:          "plugin ignores server stream issued challenge",
			pluginImpl:    &fakeV1Plugin{payload: payload},
			streamImpl:    streamBuilder.ExpectThenChallenge(payload, challenge).Build(),
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(test): plugin closed stream before handling the challenge",
		},
		{
			test:          "plugin fails responding to challenge",
			pluginImpl:    &fakeV1Plugin{payload: payload, challengeResponses: challengeResponses(challenge, challengeResponse), challengeResponseErr: errors.New("ohno")},
			streamImpl:    streamBuilder.ExpectThenChallenge(payload, challenge).Build(),
			expectCode:    codes.Unknown,
			expectMessage: "nodeattestor(test): ohno",
		},
		{
			test:          "plugin answers server stream issued challenge correctly",
			pluginImpl:    &fakeV1Plugin{payload: payload, challengeResponses: challengeResponses(challenge, challengeResponse)},
			streamImpl:    streamBuilder.ExpectThenChallenge(payload, challenge).ExpectAndBuild(challengeResponse),
			expectCode:    codes.OK,
			expectMessage: "",
		},
		{
			test:          "plugin answers server stream issued challenge incorrectly",
			pluginImpl:    &fakeV1Plugin{payload: payload, challengeResponses: challengeResponses(challenge, []byte("foo"))},
			streamImpl:    streamBuilder.ExpectThenChallenge(payload, challenge).ExpectAndBuild(challengeResponse),
			expectCode:    codes.InvalidArgument,
			expectMessage: `expected attestation payload "challengeResponse"; got "foo"`,
		},
		{
			test:          "plugin response with empty challenge response",
			pluginImpl:    &fakeV1Plugin{payload: payload, challengeResponses: challengeResponses(challenge, nil)},
			streamImpl:    streamBuilder.ExpectThenChallenge(payload, challenge).ExpectAndBuild(challengeResponse),
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(test): plugin response missing challenge response",
		},
	} {
		tt := tt
		t.Run(tt.test, func(t *testing.T) {
			nodeattestor := loadV1Plugin(t, tt.pluginImpl)
			err := nodeattestor.Attest(context.Background(), tt.streamImpl)
			if tt.expectCode != codes.OK {
				spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMessage)
				return
			}
			require.NoError(t, err)
		})
	}
}

func loadV1Plugin(t *testing.T, fake *fakeV1Plugin) nodeattestor.NodeAttestor {
	server := nodeattestorv1.NodeAttestorPluginServer(fake)

	v1 := new(nodeattestor.V1)
	plugintest.Load(t, catalog.MakeBuiltIn("test", server), v1)
	return v1
}

type fakeV1Plugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer

	closeStream bool
	payload     []byte
	payloadErr  error

	challengeResponses   map[string]string
	challengeResponseErr error
}

func (plugin *fakeV1Plugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	if plugin.closeStream {
		return nil
	}
	if plugin.payloadErr != nil {
		return plugin.payloadErr
	}

	payloadResp := &nodeattestorv1.PayloadOrChallengeResponse{}
	if plugin.payload != nil {
		payloadResp.Data = &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: plugin.payload,
		}
	}

	if err := stream.Send(payloadResp); err != nil {
		return err
	}

	for len(plugin.challengeResponses) > 0 {
		req, err := stream.Recv()
		if err != nil {
			return err
		}
		challenge := string(req.Challenge)
		if plugin.challengeResponseErr != nil {
			return plugin.challengeResponseErr
		}
		response, ok := plugin.challengeResponses[challenge]
		if !ok {
			return fmt.Errorf("test not configured to handle challenge %q", challenge)
		}
		delete(plugin.challengeResponses, challenge)
		if err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
			Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{
				ChallengeResponse: []byte(response),
			},
		}); err != nil {
			return err
		}
	}

	return nil
}

func challengeResponses(ss ...[]byte) map[string]string {
	set := make(map[string]string)
	for i := 0; i < len(ss); i += 2 {
		set[string(ss[i])] = string(ss[i+1])
	}
	return set
}
