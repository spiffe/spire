package main

import (
//	"errors"
	"net/url"
	"path"
	"sync"
	"strings"

	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/hcl"

	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"


)

const (
	pluginName = "aws_iam_role"
)

type IamRoleConfig struct {
	TrustDomain string `hcl:"trust_domain"`

	stsClient stsiface.STSAPI
}

type IamRolePlugin struct {
	iamRoleArn string
	trustDomain string
	stsClient stsiface.STSAPI

	mtx *sync.RWMutex
}

func (p *IamRolePlugin) spiffeID() *url.URL {
	spiffePath := path.Join("spire", "agent", pluginName, parseIamRole(p.iamRoleArn))
	id := &url.URL{
		Scheme: "spiffe",
		Host: p.trustDomain,
		Path: spiffePath,
	}

	return id
}

func parseIamRole (arn string) (agent_id string) {
	tokens := strings.Split(arn, ":")
	token_length := len(tokens) - 2
	relevant_tokens := tokens[token_length:]
	return strings.Join(relevant_tokens, "/")
}

func (p *IamRolePlugin) FetchAttestationData(req *nodeattestor.FetchAttestationDataRequest) (*nodeattestor.FetchAttestationDataResponse, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	input := sts.GetCallerIdentityInput{}

	result, err := p.stsClient.GetCallerIdentity(&input)
	if err != nil {
		return nil, err
	}

	// pull out role arn and put it into the p.iamRoleArn
	p.iamRoleArn = *result.Arn

	// Change the proto to just take plain byte here
	data := &common.AttestedData{
		Type: pluginName,
		Data: []byte(p.iamRoleArn),
	}

	resp := &nodeattestor.FetchAttestationDataResponse{
		AttestedData: data,
		SpiffeId:     p.spiffeID().String(),
	}

	return resp, nil

}

func (p *IamRolePlugin) Configure(req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	resp := &spi.ConfigureResponse{}

	// Parse HCL config payload into config struct
	config := &IamRoleConfig{}
	hclTree, err := hcl.Parse(req.Configuration)
	if err != nil {
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}
	err = hcl.DecodeObject(&config, hclTree)
	if err != nil {
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}

	// Set local vars from config struct
	p.trustDomain = config.TrustDomain

	return resp, nil
}

func (*IamRolePlugin) GetPluginInfo(*spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func DefaultConfig() (config IamRoleConfig) {
	return IamRoleConfig{
		TrustDomain: "example.org",
		stsClient: sts.New(session.New()),
	}

}

func New(config IamRoleConfig) nodeattestor.NodeAttestor {

	return &IamRolePlugin{
		mtx: &sync.RWMutex{},
		stsClient: config.stsClient,
	}
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: nodeattestor.Handshake,
		Plugins: map[string]plugin.Plugin{
			pluginName: nodeattestor.NodeAttestorPlugin{
				NodeAttestorImpl: New(DefaultConfig())},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
