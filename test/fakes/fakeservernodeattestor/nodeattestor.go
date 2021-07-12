package fakeservernodeattestor

import (
	"fmt"
	"testing"

	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/zeebo/errs"
)

const (
	defaultTrustDomain = "example.org"
)

type Config struct {
	// DisallowReattestation determines whether or not the attestor allows reattestation
	DisallowReattestation bool

	// TrustDomain is the trust domain for SPIFFE IDs created by the attestor.
	// Defaults to "example.org" if empty.
	TrustDomain string

	// Payloads is a map from attestation payload (as a string) to the
	// associated id produced by the attestor. For example, a mapping from
	// "DATA" ==> "FOO means that an attestation request with the data "DATA"
	// would result in an attestation response with the SPIFFE ID:
	//
	// spiffe://<trustdomain>/spire/agent/<name>/<ID>
	//
	// For example, "spiffe://example.org/spire/agent/foo/bar"
	// In case ReturnLiteral is true value will be returned as base id
	Payloads map[string]string

	// Challenges is a map from ID to a list of echo challenges. The response
	// to each challenge is expected to match the challenge value.
	Challenges map[string][]string

	// Selectors is a map from ID to a list of selector values to return with that id.
	Selectors map[string][]string

	// Return literal from Payloads map
	ReturnLiteral bool
}

func New(t *testing.T, name string, config Config) nodeattestor.NodeAttestor {
	if config.TrustDomain == "" {
		config.TrustDomain = defaultTrustDomain
	}
	plugin := &nodeAttestor{
		name:   name,
		config: config,
	}

	v0 := new(nodeattestor.V1)
	plugintest.Load(t, catalog.MakeBuiltIn(name, nodeattestorv1.NodeAttestorPluginServer(plugin)), v0)
	return v0
}

type nodeAttestor struct {
	nodeattestorv1.UnsafeNodeAttestorServer

	name   string
	config Config
}

func (p *nodeAttestor) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) (err error) {
	req, err := stream.Recv()
	if err != nil {
		return errs.Wrap(err)
	}

	payload := req.GetPayload()
	if payload == nil {
		return errs.New("request is missing payload")
	}

	id, ok := p.config.Payloads[string(payload)]
	if !ok {
		return errs.New("no ID configured for attestation data %q", string(payload))
	}

	// challenge/response loop
	for _, challenge := range p.config.Challenges[id] {
		if err := stream.Send(&nodeattestorv1.AttestResponse{
			Response: &nodeattestorv1.AttestResponse_Challenge{
				Challenge: []byte(challenge),
			},
		}); err != nil {
			return errs.Wrap(err)
		}

		responseReq, err := stream.Recv()
		if err != nil {
			return errs.Wrap(err)
		}

		challengeResponse := responseReq.GetChallengeResponse()
		if challenge != string(challengeResponse) {
			return errs.New("invalid response to echo challenge %q: got %q", challenge, string(challengeResponse))
		}
	}

	resp := &nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       p.getAgentID(id),
				SelectorValues: p.config.Selectors[id],
			},
		},
	}

	if err := stream.Send(resp); err != nil {
		return errs.Wrap(err)
	}

	return nil
}

func (p *nodeAttestor) getAgentID(id string) string {
	if p.config.ReturnLiteral {
		return id
	}

	return fmt.Sprintf("spiffe://%s/spire/agent/%s/%s", p.config.TrustDomain, p.name, id)
}
