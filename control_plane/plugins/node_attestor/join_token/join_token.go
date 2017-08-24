package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"time"

	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/sri/control_plane/plugins/node_attestor"
	common "github.com/spiffe/sri/pkg/common/plugin"
)

type JoinTokenConfig struct {
	JoinTokens  map[string]int `json:"join_tokens"`
	TrustDomain string         `json:"trust_domain"`
}

type JoinTokenPlugin struct {
	ConfigTime time.Time

	joinTokens  map[string]int
	trustDomain string
}

func (p *JoinTokenPlugin) spiffeID(token string) *url.URL {
	spiffePath := path.Join("spiffe", "node-id", token)
	id := &url.URL{
		Scheme: "spiffe",
		Host:   p.trustDomain,
		Path:   spiffePath,
	}

	return id
}

func (p *JoinTokenPlugin) Attest(req *cpnodeattestor.AttestRequest) (*cpnodeattestor.AttestResponse, error) {
	joinToken := string(req.AttestedData.Data)

	// OK to echo the token here because it becomes public knowledge after attestation
	if req.AttestedBefore {
		err := fmt.Errorf("Join token %s has been used and is no longer valid", joinToken)
		return &cpnodeattestor.AttestResponse{Valid: false}, err
	}

	tokenTTL, ok := p.joinTokens[joinToken]
	if !ok {
		err := errors.New("Unknown or expired join token")
		return &cpnodeattestor.AttestResponse{Valid: false}, err
	}

	// Check for expiration
	ttlDuration := time.Duration(tokenTTL) * time.Second
	if time.Since(p.ConfigTime) > ttlDuration {
		delete(p.joinTokens, joinToken)
		err := errors.New("Expired join token")
		return &cpnodeattestor.AttestResponse{Valid: false}, err
	}

	resp := &cpnodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: p.spiffeID(joinToken).String(),
	}
	delete(p.joinTokens, joinToken)
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
	p.ConfigTime = time.Now()
	p.joinTokens = config.JoinTokens
	p.trustDomain = config.TrustDomain

	return &common.ConfigureResponse{}, nil
}

func (*JoinTokenPlugin) GetPluginInfo(*common.GetPluginInfoRequest) (*common.GetPluginInfoResponse, error) {
	return &common.GetPluginInfoResponse{}, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: cpnodeattestor.Handshake,
		Plugins: map[string]plugin.Plugin{
			"join_token": cpnodeattestor.NodeAttestorPlugin{NodeAttestorImpl: &JoinTokenPlugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
