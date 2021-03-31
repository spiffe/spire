package nodeattestor_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	nodeattestorv0 "github.com/spiffe/spire/proto/spire/plugin/agent/nodeattestor/v0"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestV0(t *testing.T) {
	attestationData := nodeattestor.AttestationData{Type: "test", Payload: []byte("test")}
	attestationDataMissingType := nodeattestor.AttestationData{Payload: []byte("test")}
	attestationDataMissingPayload := nodeattestor.AttestationData{Type: "test"}

	for _, tt := range []struct {
		test          string
		pluginImpl    *fakeV0Plugin
		streamImpl    *fakeStream
		expectCode    codes.Code
		expectMessage string
	}{
		{
			test:          "plugin closes stream without returning attestation data",
			pluginImpl:    &fakeV0Plugin{closeStream: true},
			streamImpl:    &fakeStream{},
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(test): plugin closed stream before returning attestation data",
		},
		{
			test:          "plugin fails fetching attestation data",
			pluginImpl:    &fakeV0Plugin{attestationDataErr: errors.New("ohno")},
			streamImpl:    &fakeStream{},
			expectCode:    codes.Unknown,
			expectMessage: "nodeattestor(test): ohno",
		},
		{
			test:          "plugin does not return attestation data",
			pluginImpl:    &fakeV0Plugin{},
			streamImpl:    &fakeStream{},
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(test): plugin response missing attestation data",
		},
		{
			test:          "plugin does not return attestation data type",
			pluginImpl:    &fakeV0Plugin{attestationData: &attestationDataMissingType},
			streamImpl:    &fakeStream{},
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(test): plugin response missing attestation data type",
		},
		{
			test:          "plugin does not return attestation data payload",
			pluginImpl:    &fakeV0Plugin{attestationData: &attestationDataMissingPayload},
			streamImpl:    &fakeStream{},
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(test): plugin response missing attestation data payload",
		},
		{
			test:          "server stream fails sending attestation data",
			pluginImpl:    &fakeV0Plugin{attestationData: &attestationData},
			streamImpl:    &fakeStream{attestationErr: errors.New("ohno")},
			expectCode:    codes.Unknown,
			expectMessage: "ohno",
		},
		{
			test:          "server stream issues no challenge",
			pluginImpl:    &fakeV0Plugin{attestationData: &attestationData},
			streamImpl:    &fakeStream{expectData: attestationData},
			expectCode:    codes.OK,
			expectMessage: "",
		},
		{
			test:          "plugin ignores server stream issued challenge",
			pluginImpl:    &fakeV0Plugin{attestationData: &attestationData},
			streamImpl:    &fakeStream{expectData: attestationData, challenges: challenges("echo")},
			expectCode:    codes.Internal,
			expectMessage: "nodeattestor(test): plugin closed stream before handling the challenge",
		},
		{
			test:          "plugin fails responding to challenge",
			pluginImpl:    &fakeV0Plugin{attestationData: &attestationData, challengeResponses: challengeResponses("echo", "echo"), challengeResponseErr: errors.New("ohno")},
			streamImpl:    &fakeStream{expectData: attestationData, challenges: challenges("echo")},
			expectCode:    codes.Unknown,
			expectMessage: "nodeattestor(test): ohno",
		},
		{
			test:          "plugin answers server stream issued challenge correctly",
			pluginImpl:    &fakeV0Plugin{attestationData: &attestationData, challengeResponses: challengeResponses("echo", "echo")},
			streamImpl:    &fakeStream{expectData: attestationData, challenges: challenges("echo")},
			expectCode:    codes.OK,
			expectMessage: "",
		},
		{
			test:          "plugin answers server stream issued challenge incorrectly",
			pluginImpl:    &fakeV0Plugin{attestationData: &attestationData, challengeResponses: challengeResponses("echo", "foo")},
			streamImpl:    &fakeStream{expectData: attestationData, challenges: challenges("echo")},
			expectCode:    codes.InvalidArgument,
			expectMessage: "stream received invalid challenge response",
		},
		{
			test:          "plugin response with empty challenge response",
			pluginImpl:    &fakeV0Plugin{attestationData: &attestationData, challengeResponses: challengeResponses("echo", "")},
			streamImpl:    &fakeStream{expectData: attestationData, challenges: challenges("echo")},
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
	server := nodeattestorv0.PluginServer(fake)

	var plugin nodeattestor.V0
	spiretest.LoadPlugin(t, catalog.MakePlugin("test", server), &plugin)
	return plugin
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

type fakeStream struct {
	attestationErr error
	expectData     nodeattestor.AttestationData
	challenges     []string
}

func (ss *fakeStream) SendAttestationData(ctx context.Context, attestationData nodeattestor.AttestationData) ([]byte, error) {
	switch {
	case ss.attestationErr != nil:
		return nil, ss.attestationErr
	case ss.expectData.Type != attestationData.Type:
		return nil, fmt.Errorf("expected attestation type %q; got %q", ss.expectData.Type, attestationData.Type)
	case string(ss.expectData.Payload) != string(attestationData.Payload):
		return nil, fmt.Errorf("expected attestation payload %q; got %q", string(ss.expectData.Payload), string(attestationData.Payload))
	default:
		return ss.nextChallenge(), nil
	}
}

func (ss *fakeStream) SendChallengeResponse(ctx context.Context, response []byte) ([]byte, error) {
	switch {
	case len(ss.challenges) == 0:
		// This shouldn't happen unless there is a problem in the shim since
		// it shouldn't be issuing challenge responses for challenges that
		// were never issued.
		return nil, errors.New("stream received unexpected challenge response")
	case ss.challenges[0] != string(response):
		return nil, status.Error(codes.InvalidArgument, "stream received invalid challenge response")
	}
	ss.challenges = ss.challenges[1:]
	return ss.nextChallenge(), nil
}

func (ss *fakeStream) nextChallenge() []byte {
	if len(ss.challenges) > 0 {
		return []byte(ss.challenges[0])
	}
	return nil
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

func challenges(ss ...string) []string {
	return ss
}

func challengeResponses(ss ...string) map[string]string {
	set := make(map[string]string)
	for i := 0; i < len(ss); i += 2 {
		set[ss[i]] = ss[i+1]
	}
	return set
}
