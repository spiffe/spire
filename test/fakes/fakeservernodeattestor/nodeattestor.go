package fakeservernodeattestor

import (
	"context"
	"fmt"
	"testing"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	nodeattestorv0 "github.com/spiffe/spire/proto/spire/plugin/server/nodeattestor/v0"
	"github.com/spiffe/spire/test/spiretest"
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

	// Data is a map from attestation data (as a string) to the associated id
	// produced by the attestor. For example, a mapping from "DATA" ==> "FOO
	// means that an attestation request with the data "DATA" would result in
	// an attestation response with the SPIFFE ID:
	//
	// spiffe://<trustdomain>/spire/agent/<name>/<ID>
	//
	// For example, "spiffe://example.org/spire/agent/foo/bar"
	// In case ReturnLiteral is true value will be returned as base id
	Data map[string]string

	// Challenges is a map from ID to a list of echo challenges. The response
	// to each challenge is expected to match the challenge value.
	Challenges map[string][]string

	// Selectors is a map from ID to a list of selector values to return with that id.
	Selectors map[string][]string

	// Return literal from Data map
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

	var na nodeattestor.V0
	spiretest.LoadPlugin(t, catalog.MakePlugin(name, nodeattestorv0.PluginServer(plugin)), &na)
	return na
}

type nodeAttestor struct {
	nodeattestorv0.UnsafeNodeAttestorServer

	name   string
	config Config
}

func (p *nodeAttestor) Attest(stream nodeattestorv0.NodeAttestor_AttestServer) (err error) {
	req, err := stream.Recv()
	if err != nil {
		return errs.Wrap(err)
	}

	if req.AttestationData == nil {
		return errs.New("request is missing attestation data")
	}

	if req.AttestationData.Type != p.name {
		return errs.New("request has wrong attestation data type: expected %q got %q", p.name, req.AttestationData.Type)
	}

	id, ok := p.config.Data[string(req.AttestationData.Data)]
	if !ok {
		return errs.New("no ID configured for attestation data %q", string(req.AttestationData.Data))
	}

	// challenge/response loop
	for _, challenge := range p.config.Challenges[id] {
		if err := stream.Send(&nodeattestorv0.AttestResponse{
			Challenge: []byte(challenge),
		}); err != nil {
			return errs.Wrap(err)
		}

		responseReq, err := stream.Recv()
		if err != nil {
			return errs.Wrap(err)
		}

		if challenge != string(responseReq.Response) {
			return errs.New("invalid response to echo challenge %q: got %q", challenge, string(responseReq.Response))
		}
	}

	resp := &nodeattestorv0.AttestResponse{
		AgentId: p.getAgentID(id),
	}

	for _, value := range p.config.Selectors[id] {
		resp.Selectors = append(resp.Selectors, &common.Selector{
			Type:  p.name,
			Value: value,
		})
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

func (p *nodeAttestor) Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return &plugin.ConfigureResponse{}, nil
}

func (p *nodeAttestor) GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}
