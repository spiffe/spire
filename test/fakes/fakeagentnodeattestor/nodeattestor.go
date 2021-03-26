package fakeagentnodeattestor

import (
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common"
	nodeattestorv0 "github.com/spiffe/spire/proto/spire/plugin/agent/nodeattestor/v0"
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
	server := nodeattestorv0.NodeAttestorPluginServer(&nodeAttestor{
		config: config,
	})

	na := new(nodeattestor.V0)
	plugintest.Load(t, catalog.MakeBuiltIn("fake", server), na)
	return na
}

type nodeAttestor struct {
	nodeattestorv0.UnimplementedNodeAttestorServer

	config Config
}

func (p *nodeAttestor) FetchAttestationData(stream nodeattestorv0.NodeAttestor_FetchAttestationDataServer) (err error) {
	if p.config.Fail {
		return errors.New("fetching attestation data failed by test")
	}

	if err := stream.Send(p.makeResponse(nil)); err != nil {
		return err
	}

	responsesLeft := p.config.Responses

	for {
		req, err := stream.Recv()
		switch {
		case err == io.EOF:
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
			if err := stream.Send(p.makeResponse([]byte(responsesLeft[0]))); err != nil {
				return err
			}
			responsesLeft = responsesLeft[1:]
		}
		if err == io.EOF {
			return nil
		}
	}
}

func (p *nodeAttestor) makeResponse(challengeResponse []byte) *nodeattestorv0.FetchAttestationDataResponse {
	if challengeResponse != nil {
		return &nodeattestorv0.FetchAttestationDataResponse{
			Response: challengeResponse,
		}
	}

	return &nodeattestorv0.FetchAttestationDataResponse{
		AttestationData: &common.AttestationData{
			Type: "test",
			Data: []byte("TEST"),
		},
	}
}
