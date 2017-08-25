package main

import (
	"encoding/json"
	"errors"
	"net/url"
	"path"

	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/sri/pkg/common/plugin"
	"github.com/spiffe/sri/pkg/agent/nodeattestor"
)

type JoinTokenConfig struct {
	JoinToken   string `json:"join_token"`
	TrustDomain string `json:"trust_domain"`
}

type JoinTokenPlugin struct {
	joinToken   string
	trustDomain string
}

func (p *JoinTokenPlugin) spiffeID() *url.URL {
	spiffePath := path.Join("spiffe", "node-id", p.joinToken)
	id := &url.URL{
		Scheme: "spiffe",
		Host:   p.trustDomain,
		Path:   spiffePath,
	}

	return id
}

func (p *JoinTokenPlugin) FetchAttestationData(req *nodeattestor.FetchAttestationDataRequest) (*nodeattestor.FetchAttestationDataResponse, error) {
	if p.joinToken == "" {
		err := errors.New("Join token attestation attempted but no token provided")
		return &nodeattestor.FetchAttestationDataResponse{}, err
	}

	// FIXME: NA should be the one dictating type of this message
	// Change the proto to just take plain byte here
	data := &nodeattestor.AttestedData{
		Type: "join_token",
		Data: []byte(p.joinToken),
	}

	resp := &nodeattestor.FetchAttestationDataResponse{
		AttestedData: data,
		SpiffeId:     p.spiffeID().String(),
	}

	return resp, nil
}

func (p *JoinTokenPlugin) Configure(req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	// Parse JSON config payload into config struct
	config := &JoinTokenConfig{}
	if err := json.Unmarshal([]byte(req.Configuration), &config); err != nil {
		resp := &sriplugin.ConfigureResponse{
			ErrorList: []string{err.Error()},
		}
		return resp, err
	}

	// Set local vars from config struct
	p.joinToken = config.JoinToken
	p.trustDomain = config.TrustDomain

	return &sriplugin.ConfigureResponse{}, nil
}

func (*JoinTokenPlugin) GetPluginInfo(*sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	return &sriplugin.GetPluginInfoResponse{}, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: nodeattestor.Handshake,
		Plugins: map[string]plugin.Plugin{
			"join_token": nodeattestor.NodeAttestorPlugin{NodeAttestorImpl: &JoinTokenPlugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
