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
	trustDomain        string
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
		return newError("request missing attestation data")
	}

	if attestationData.Type != gcp.PluginName {
		return newErrorf("unexpected attestation data type %q", attestationData.Type)
	}

	if req.AttestedBefore {
		return newError("instance ID has already been attested")
	}

	identityToken := &gcp.IdentityToken{}
	_, err = jwt.ParseWithClaims(string(req.GetAttestationData().Data), identityToken, p.tokenKeyRetriever.retrieveKey)
	if err != nil {
		return newErrorf("unable to parse/validate the identity token: %v", err)
	}

	if identityToken.Audience != tokenAudience {
		return newErrorf("unexpected identity token audience %q", identityToken.Audience)
	}

	projectIDMatchesWhitelist := false
	for _, projectID := range c.ProjectIDWhitelist {
		if identityToken.Google.ComputeEngine.ProjectID == projectID {
			projectIDMatchesWhitelist = true
			break
		}
	}
	if !projectIDMatchesWhitelist {
		return newErrorf("identity token project ID %q is not in the whitelist", identityToken.Google.ComputeEngine.ProjectID)
	}

	spiffeID := gcp.MakeSpiffeID(c.trustDomain, identityToken.Google.ComputeEngine.ProjectID, identityToken.Google.ComputeEngine.InstanceID)

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
		return nil, newErrorf("unable to decode configuration: %v", err)
	}

	if req.GlobalConfig == nil {
		return nil, newError("global configuration is required")
	}

	if req.GlobalConfig.TrustDomain == "" {
		return nil, newError("trust_domain is required")
	}
	config.trustDomain = req.GlobalConfig.TrustDomain

	if len(config.ProjectIDWhitelist) == 0 {
		return nil, newError("projectid_whitelist is required")
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
		return nil, newError("not configured")
	}
	return p.config, nil
}

func newError(msg string) error {
	return errors.New("gcp-iit: " + msg)
}

func newErrorf(format string, args ...interface{}) error {
	return fmt.Errorf("gcp-iit: "+format, args...)
}
