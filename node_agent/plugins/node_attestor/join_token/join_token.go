package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/sri/common/plugin"
	"github.com/spiffe/sri/node_agent/plugins/node_attestor"
)

type JoinTokenConfig struct {
	JoinToken   string `json:"join_token"`
	TrustDomain string `json:"trust_domain"`
}

type JoinTokenPlugin struct {
	joinToken   string
	trustDomain string
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

	spiffeId := fmt.Sprintf("spiffe://%s/spiffe/node-id/%s", p.trustDomain, p.joinToken)
	resp := &nodeattestor.FetchAttestationDataResponse{
		AttestedData: data,
		SpiffeId:     spiffeId,
	}

	return resp, nil
}

func (p *JoinTokenPlugin) Configure(req *common.ConfigureRequest) (*common.ConfigureResponse, error) {
	// Parse JSON config payload into config struct
	config := &JoinTokenConfig{}
	if err := json.Unmarshal([]byte(req.Configuration), &config); err != nil {
		resp := &common.ConfigureResponse{
			ErrorList: []string{err.Error()},
		}
		return resp, err
	}

	// Set local vars from config struct
	p.joinToken = config.JoinToken
	p.trustDomain = config.TrustDomain

	return &common.ConfigureResponse{}, nil
}

func (*JoinTokenPlugin) GetPluginInfo(*common.GetPluginInfoRequest) (*common.GetPluginInfoResponse, error) {
	return &common.GetPluginInfoResponse{}, nil
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
