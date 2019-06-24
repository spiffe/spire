package fakeagentnodeattestor

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spiffe/spire/proto/spire/agent/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/common/plugin"
)

type Config struct {
	// Fail indicates whether or not fetching attestation data should fail.
	Fail bool

	// DeprecatedAgentID is the SPIFFE ID of the agent. If set, it will be
	// returned with the attestation response.
	DeprecatedAgentID string

	// Responses is list of echo responses. The response to each challenge is
	// expected to match the challenge value.
	Responses []string
}

type NodeAttestor struct {
	config Config
}

func New(config Config) *NodeAttestor {
	return &NodeAttestor{
		config: config,
	}
}

func (p *NodeAttestor) FetchAttestationData(stream nodeattestor.NodeAttestor_FetchAttestationDataServer) (err error) {
	if p.config.Fail {
		return errors.New("fetching attestation data purposefully failed")
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

func (p *NodeAttestor) Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return &plugin.ConfigureResponse{}, nil
}

func (p *NodeAttestor) GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}

func (p *NodeAttestor) makeResponse(challengeResponse []byte) *nodeattestor.FetchAttestationDataResponse {
	return &nodeattestor.FetchAttestationDataResponse{
		AttestationData: &common.AttestationData{
			Type: "test",
			Data: []byte("TEST"),
		},
		Response:           challengeResponse,
		DEPRECATEDSpiffeId: p.config.DeprecatedAgentID,
	}
}
