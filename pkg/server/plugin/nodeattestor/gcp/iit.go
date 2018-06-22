package gcp

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/hcl"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/spiffe/spire/pkg/common/plugin/gcp"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"
)

const (
	tokenAudience = "spire-gcp-node-attestor"
	googleCertURL = "https://www.googleapis.com/oauth2/v1/certs"
)

type tokenKeyRetriever interface {
	retrieveKey(token *jwt.Token) (interface{}, error)
}

type IITAttestorConfig struct {
	TrustDomain        string   `hcl:"trust_domain"`
	ProjectIDWhitelist []string `hcl:"projectid_whitelist"`
}

type IITAttestorPlugin struct {
	tokenKeyRetriever tokenKeyRetriever

	mtx    sync.Mutex
	config *IITAttestorConfig
}

func (p *IITAttestorPlugin) Attest(stream nodeattestor.Attest_PluginStream) error {
	c, err := p.getConfig()
	if err != nil {
		return err
	}

	req, err := stream.Recv()
	if err != nil {
		return err
	}

	attestationData := req.GetAttestationData()
	if attestationData == nil {
		return gcp.AttestationStepError("retrieving the attested data", errors.New("missing attestation data"))
	}

	if attestationData.Type != gcp.PluginName {
		return gcp.AttestationStepError("retrieving the attested data", errors.New("invalid attestation data type"))
	}

	if req.AttestedBefore {
		return gcp.AttestationStepError("validation the InstanceID", fmt.Errorf("the InstanceID has been used and cannot be registered again"))
	}

	identityToken := &gcp.IdentityToken{}
	_, err = jwt.ParseWithClaims(string(req.GetAttestationData().Data), identityToken, p.tokenKeyRetriever.retrieveKey)
	if err != nil {
		return gcp.AttestationStepError("parsing the identity token", err)
	}

	if identityToken.Audience != tokenAudience {
		return gcp.AttestationStepError("Audience claim in the token doesn't match the expected audience", err)
	}

	projectIDMatchesWhitelist := false
	for _, projectID := range c.ProjectIDWhitelist {
		if identityToken.Google.ComputeEngine.ProjectID == projectID {
			projectIDMatchesWhitelist = true
			break
		}
	}
	if !projectIDMatchesWhitelist {
		return gcp.AttestationStepError("validation of the ProjectID", errors.New("the projectID doesn't match the projectID whitelist"))
	}

	spiffeID := gcp.MakeSpiffeID(c.TrustDomain, identityToken.Google.ComputeEngine.ProjectID, identityToken.Google.ComputeEngine.InstanceID)

	resp := &nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: spiffeID,
	}

	if err := stream.Send(resp); err != nil {
		return err
	}

	return nil
}

func (p *IITAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config := &IITAttestorConfig{}
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, fmt.Errorf("Error parsing GCP IIT Attestor configuration %v", err)
	}
	if config.TrustDomain == "" {
		return nil, fmt.Errorf("Missing trust_domain configuration parameter")
	}
	if len(config.ProjectIDWhitelist) == 0 {
		return nil, fmt.Errorf("Missing projectid_whitelist configuration parameter")
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = config

	return &spi.ConfigureResponse{}, nil
}

func (*IITAttestorPlugin) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func NewIITAttestorPlugin() *IITAttestorPlugin {
	return &IITAttestorPlugin{
		tokenKeyRetriever: newGooglePublicKeyRetriever(googleCertURL),
	}
}

func (p *IITAttestorPlugin) getConfig() (*IITAttestorConfig, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	if p.config == nil {
		return nil, errors.New("gcp-iit: not configured")
	}
	return p.config, nil
}
