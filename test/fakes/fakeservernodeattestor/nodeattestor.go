package fakeservernodeattestor

import (
	"context"
	"fmt"

	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/nodeattestor"
	"github.com/zeebo/errs"
)

const (
	defaultTrustDomain = "example.org"
)

type Config struct {
	// CanReattest determines whether or not the attestor allows reattestation
	CanReattest bool

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
	Data map[string]string

	// Challenges is a map from ID to a list of echo challenges. The response
	// to each challenge is expected to match the challenge value.
	Challenges map[string][]string

	// Selectors is a map from ID to a list of selector values to return with that id.
	Selectors map[string][]string
}

type NodeAttestor struct {
	name   string
	config Config
}

func New(name string, config Config) *NodeAttestor {
	if config.TrustDomain == "" {
		config.TrustDomain = defaultTrustDomain
	}
	return &NodeAttestor{
		name:   name,
		config: config,
	}
}

func (p *NodeAttestor) Attest(stream nodeattestor.NodeAttestor_AttestServer) (err error) {
	req, err := stream.Recv()
	if err != nil {
		return errs.Wrap(err)
	}

	if req.AttestedBefore && !p.config.CanReattest {
		return errs.New("reattestation is not permitted")
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
		if err := stream.Send(&nodeattestor.AttestResponse{
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

	resp := &nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: fmt.Sprintf("spiffe://%s/spire/agent/%s/%s", p.config.TrustDomain, p.name, id),
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

func (p *NodeAttestor) Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return &plugin.ConfigureResponse{}, nil
}

func (p *NodeAttestor) GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}
