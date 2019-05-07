package gcp

import (
	"context"
	"sync"
	"text/template"

	"github.com/hashicorp/hcl"
	"github.com/zeebo/errs"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/gcp"
	nodeattestorbase "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/base"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/nodeattestor"
)

var (
	pluginErr = errs.Class("gcp-iit")
)

const (
	tokenAudience = "spire-gcp-node-attestor"
	googleCertURL = "https://www.googleapis.com/oauth2/v1/certs"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *IITAttestorPlugin) catalog.Plugin {
	return catalog.MakePlugin("gcp_iit",
		nodeattestor.PluginServer(p),
	)
}

type tokenKeyRetriever interface {
	retrieveKey(token *jwt.Token) (interface{}, error)
}

// IITAttestorPlugin implements node attestation for agents running in GCP.
type IITAttestorPlugin struct {
	nodeattestorbase.Base
	config            *IITAttestorConfig
	mtx               sync.Mutex
	tokenKeyRetriever tokenKeyRetriever
}

// IITAttestorConfig is the config for IITAttestorPlugin.
type IITAttestorConfig struct {
	idPathTemplate     *template.Template
	trustDomain        string
	ProjectIDWhitelist []string `hcl:"projectid_whitelist"`
	AgentPathTemplate  string   `hcl:"agent_path_template"`
}

// New creates a new IITAttestorPlugin.
func New() *IITAttestorPlugin {
	return &IITAttestorPlugin{
		tokenKeyRetriever: newGooglePublicKeyRetriever(googleCertURL),
	}
}

// Attest implements the server side logic for the gcp iit node attestation plugin.
func (p *IITAttestorPlugin) Attest(stream nodeattestor.NodeAttestor_AttestServer) error {
	c, err := p.getConfig()
	if err != nil {
		return err
	}

	identityMetadata, err := validateAttestationAndExtractIdentityMetadata(stream, gcp.PluginName, p.tokenKeyRetriever)
	if err != nil {
		return err
	}

	projectIDMatchesWhitelist := false
	for _, projectID := range c.ProjectIDWhitelist {
		if identityMetadata.ProjectID == projectID {
			projectIDMatchesWhitelist = true
			break
		}
	}
	if !projectIDMatchesWhitelist {
		return newErrorf("identity token project ID %q is not in the whitelist", identityMetadata.ProjectID)
	}

	id, err := gcp.MakeSpiffeID(c.trustDomain, c.idPathTemplate, identityMetadata)
	if err != nil {
		return newErrorf("failed to create spiffe ID: %v", err)
	}

	attested, err := p.IsAttested(stream.Context(), id.String())
	switch {
	case err != nil:
		return pluginErr.Wrap(err)
	case attested:
		return pluginErr.New("IIT has already been used to attest an agent")
	}

	resp := &nodeattestor.AttestResponse{
		AgentId: id.String(),
	}

	if err := stream.Send(resp); err != nil {
		return err
	}

	return nil
}

// Configure configures the IITAttestorPlugin.
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

	tmpl := gcp.DefaultAgentPathTemplate
	if len(config.AgentPathTemplate) > 0 {
		var err error
		tmpl, err = template.New("agent-path").Parse(config.AgentPathTemplate)
		if err != nil {
			return nil, newErrorf("failed to parse agent path template: %q", config.AgentPathTemplate)
		}
	}

	config.idPathTemplate = tmpl

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = config

	return &spi.ConfigureResponse{}, nil
}

// GetPluginInfo returns the version and related metadata of the installed plugin.
func (*IITAttestorPlugin) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *IITAttestorPlugin) getConfig() (*IITAttestorConfig, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	if p.config == nil {
		return nil, newError("not configured")
	}
	return p.config, nil
}

func validateAttestationAndExtractIdentityMetadata(stream nodeattestor.NodeAttestor_AttestServer, pluginName string, tokenRetriever tokenKeyRetriever) (gcp.ComputeEngine, error) {
	req, err := stream.Recv()
	if err != nil {
		return gcp.ComputeEngine{}, err
	}

	attestationData := req.GetAttestationData()
	if attestationData == nil {
		return gcp.ComputeEngine{}, newError("request missing attestation data")
	}

	if attestationData.Type != pluginName {
		return gcp.ComputeEngine{}, newErrorf("unexpected attestation data type %q", attestationData.Type)
	}

	identityToken := &gcp.IdentityToken{}
	_, err = jwt.ParseWithClaims(string(req.GetAttestationData().Data), identityToken, tokenRetriever.retrieveKey)
	if err != nil {
		return gcp.ComputeEngine{}, newErrorf("unable to parse/validate the identity token: %v", err)
	}

	if identityToken.Audience != tokenAudience {
		return gcp.ComputeEngine{}, newErrorf("unexpected identity token audience %q", identityToken.Audience)
	}

	return identityToken.Google.ComputeEngine, nil
}

func newError(msg string) error {
	return pluginErr.New("%s", msg)
}

func newErrorf(format string, args ...interface{}) error {
	return pluginErr.New(format, args...)
}
