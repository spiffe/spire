package nodeattestor_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	nodeattestortest "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/test"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	nodeattestorv0 "github.com/spiffe/spire/proto/spire/plugin/agent/nodeattestor/v0"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestV0(t *testing.T) {
	streamBuilder := nodeattestortest.ServerStream("test")
	payload := []byte("payload")
	challenge := []byte("challenge")
	challengeResponse := []byte("challengeResponse")
	attestationData := nodeattestor.AttestationData{Type: "test", Payload: payload}
	attestationDataMissingType := nodeattestor.AttestationData{Payload: payload}
	attestationDataMissingPayload := nodeattestor.AttestationData{Type: "test"}

	for _, tt := range []struct {
		test          string
		pluginImpl    *fakeV0Plugin
		streamImpl    nodeattestor.ServerStream
		expectCode    codes.Code
		expectMessage string
	}{
		{
			test:          "plugin closes stream without returning attestation data",
			pluginImpl:    &fakeV0Plugin{closeStream: true},
			streamImpl:    streamBuilder.Build(),
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(test): plugin closed stream before returning attestation data",
		},
		{
			test:          "plugin fails fetching attestation data",
			pluginImpl:    &fakeV0Plugin{attestationDataErr: errors.New("ohno")},
			streamImpl:    streamBuilder.Build(),
			expectCode:    codes.Unknown,
			expectMessage: "nodeattestor(test): ohno",
		},
		{
			test:          "plugin does not return attestation data",
			pluginImpl:    &fakeV0Plugin{},
			streamImpl:    streamBuilder.Build(),
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(test): plugin response missing attestation data",
		},
		{
			test:          "plugin does not return attestation data type",
			pluginImpl:    &fakeV0Plugin{attestationData: &attestationDataMissingType},
			streamImpl:    streamBuilder.Build(),
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(test): plugin response missing attestation data type",
		},
		{
			test:          "plugin does not return attestation data payload",
			pluginImpl:    &fakeV0Plugin{attestationData: &attestationDataMissingPayload},
			streamImpl:    streamBuilder.Build(),
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(test): plugin response missing attestation data payload",
		},
		{
			test:          "server stream fails sending attestation data",
			pluginImpl:    &fakeV0Plugin{attestationData: &attestationData},
			streamImpl:    streamBuilder.FailAndBuild(errors.New("ohno")),
			expectCode:    codes.Unknown,
			expectMessage: "ohno",
		},
		{
			test:          "server stream issues no challenge",
			pluginImpl:    &fakeV0Plugin{attestationData: &attestationData},
			streamImpl:    streamBuilder.ExpectAndBuild(payload),
			expectCode:    codes.OK,
			expectMessage: "",
		},
		{
			test:          "plugin ignores server stream issued challenge",
			pluginImpl:    &fakeV0Plugin{attestationData: &attestationData},
			streamImpl:    streamBuilder.ExpectThenChallenge(payload, challenge).ExpectAndBuild(challengeResponse),
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(test): plugin closed stream before handling the challenge",
		},
		{
			test:          "plugin fails responding to challenge",
			pluginImpl:    &fakeV0Plugin{attestationData: &attestationData, challengeResponses: challengeResponses(challenge, challengeResponse), challengeResponseErr: errors.New("ohno")},
			streamImpl:    streamBuilder.ExpectThenChallenge(payload, challenge).ExpectAndBuild(challengeResponse),
			expectCode:    codes.Unknown,
			expectMessage: "nodeattestor(test): ohno",
		},
		{
			test:          "plugin answers server stream issued challenge correctly",
			pluginImpl:    &fakeV0Plugin{attestationData: &attestationData, challengeResponses: challengeResponses(challenge, challengeResponse)},
			streamImpl:    streamBuilder.ExpectThenChallenge(payload, challenge).ExpectAndBuild(challengeResponse),
			expectCode:    codes.OK,
			expectMessage: "",
		},
		{
			test:          "plugin answers server stream issued challenge incorrectly",
			pluginImpl:    &fakeV0Plugin{attestationData: &attestationData, challengeResponses: challengeResponses(challenge, []byte("foo"))},
			streamImpl:    streamBuilder.ExpectThenChallenge(payload, challenge).ExpectAndBuild(challengeResponse),
			expectCode:    codes.InvalidArgument,
			expectMessage: `expected attestation payload "challengeResponse"; got "foo"`,
		},
		{
			test:          "plugin response with empty challenge response",
			pluginImpl:    &fakeV0Plugin{attestationData: &attestationData, challengeResponses: challengeResponses(challenge, nil)},
			streamImpl:    streamBuilder.ExpectThenChallenge(payload, challenge).ExpectAndBuild(challengeResponse),
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(test): plugin response missing challenge response",
		},
	} {
		tt := tt
		t.Run(tt.test, func(t *testing.T) {
			nodeattestor := loadV0Plugin(t, tt.pluginImpl)
			err := nodeattestor.Attest(context.Background(), tt.streamImpl)
			if tt.expectCode != codes.OK {
				spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMessage)
				return
			}
			require.NoError(t, err)
		})
	}
}

func loadV0Plugin(t *testing.T, fake *fakeV0Plugin) nodeattestor.NodeAttestor {
	server := nodeattestorv0.NodeAttestorPluginServer(fake)

	v0 := new(nodeattestor.V0)
	plugintest.Load(t, catalog.MakeBuiltIn("test", server), v0)
	return v0
}

type fakeV0Plugin struct {
	nodeattestorv0.UnimplementedNodeAttestorServer

	closeStream        bool
	attestationData    *nodeattestor.AttestationData
	attestationDataErr error

	challengeResponses   map[string]string
	challengeResponseErr error
}

func (plugin *fakeV0Plugin) FetchAttestationData(stream nodeattestorv0.NodeAttestor_FetchAttestationDataServer) error {
	if plugin.closeStream {
		return nil
	}
	if plugin.attestationDataErr != nil {
		return plugin.attestationDataErr
	}
	if err := stream.Send(&nodeattestorv0.FetchAttestationDataResponse{
		AttestationData: v0AttestationData(plugin.attestationData),
	}); err != nil {
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
		if err := stream.Send(&nodeattestorv0.FetchAttestationDataResponse{
			Response: []byte(response),
		}); err != nil {
			return err
		}
	}

	return nil
}

func (plugin *fakeV0Plugin) Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (plugin *fakeV0Plugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func v0AttestationData(attestationData *nodeattestor.AttestationData) *common.AttestationData {
	if attestationData == nil {
		return nil
	}
	return &common.AttestationData{
		Type: attestationData.Type,
		Data: attestationData.Payload,
	}
}

func challengeResponses(ss ...[]byte) map[string]string {
	set := make(map[string]string)
	for i := 0; i < len(ss); i += 2 {
		set[string(ss[i])] = string(ss[i+1])
	}
	return set
}
