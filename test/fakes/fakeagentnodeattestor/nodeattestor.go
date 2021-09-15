package fakeagentnodeattestor

import (
	"errors"
	"fmt"
	"io"
	"testing"

	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/plugintest"
)

type Config struct {
	// Fail indicates whether or not fetching attestation data should fail.
	Fail bool

	// Responses is list of echo responses. The response to each challenge is
	// expected to match the challenge value.
	Responses []string
}

func New(t *testing.T, config Config) nodeattestor.NodeAttestor {
	server := nodeattestorv1.NodeAttestorPluginServer(&nodeAttestor{
		config: config,
	})

	na := new(nodeattestor.V1)
	plugintest.Load(t, catalog.MakeBuiltIn("fake", server), na)
	return na
}

type nodeAttestor struct {
	nodeattestorv1.UnimplementedNodeAttestorServer

	config Config
}

func (p *nodeAttestor) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) (err error) {
	if p.config.Fail {
		return errors.New("fetching attestation data failed by test")
	}

	if err := stream.Send(makePayload()); err != nil {
		return err
	}

	responsesLeft := p.config.Responses

	for {
		req, err := stream.Recv()
		switch {
		case errors.Is(err, io.EOF):
			if len(responsesLeft) > 0 {
				return fmt.Errorf("unused responses remaining: %q", responsesLeft)
			}
			return nil
		case err != nil:
			return err
		case len(responsesLeft) == 0:
			return fmt.Errorf("unexpected challenge %q", string(req.Challenge))
		case string(req.Challenge) != responsesLeft[0]:
			return fmt.Errorf("unexpected challenge %q; expected %q", string(req.Challenge), responsesLeft[0])
		default:
			if err := stream.Send(makeChallengeResponse([]byte(responsesLeft[0]))); err != nil {
				return err
			}
			responsesLeft = responsesLeft[1:]
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

func makePayload() *nodeattestorv1.PayloadOrChallengeResponse {
	return &nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: []byte("TEST"),
		},
	}
}

func makeChallengeResponse(challengeResponse []byte) *nodeattestorv1.PayloadOrChallengeResponse {
	return &nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{
			ChallengeResponse: challengeResponse,
		},
	}
}
