package azure

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/azure"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/zeebo/errs"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	pluginName = "azure_msi"
)

var (
	msiError = errs.Class("azure-msi")
)

func BuiltIn() catalog.Plugin {
	return builtIn(New())
}

func builtIn(p *MSIAttestorPlugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, nodeattestor.PluginServer(p))
}

type MSIAttestorConfig struct {
	trustDomain string

	// ResourceID assigned to the MSI token. This value is the intended
	// audience of the token, in other words, which service the token can be
	// used to authenticate with. Ideally deployments use the ID of an
	// application they registered with the active directory to limit the scope
	// of use of the token. A bogus value cannot be used; Azure makes sure the
	// resource ID is either an azure service ID or a registered app ID.
	ResourceID string `hcl:"resource_id"`
}

type MSIAttestorPlugin struct {
	mu     sync.RWMutex
	config *MSIAttestorConfig

	hooks struct {
		fetchMSIToken func(context.Context, azure.HTTPClient, string) (string, error)
	}
}

func New() *MSIAttestorPlugin {
	p := &MSIAttestorPlugin{}
	p.hooks.fetchMSIToken = azure.FetchMSIToken
	return p
}

func (p *MSIAttestorPlugin) FetchAttestationData(stream nodeattestor.NodeAttestor_FetchAttestationDataServer) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	// Obtain an MSI token from the Azure Instance Metadata Service
	token, err := p.hooks.fetchMSIToken(stream.Context(), http.DefaultClient, config.ResourceID)
	if err != nil {
		return msiError.New("unable to fetch token: %v", err)
	}

	claims, err := getUnverifiedMSITokenClaims(token)
	if err != nil {
		return msiError.Wrap(err)
	}

	data, err := json.Marshal(azure.MSIAttestationData{
		Token: token,
	})
	if err != nil {
		return msiError.Wrap(err)
	}

	return stream.Send(&nodeattestor.FetchAttestationDataResponse{
		AttestationData: &common.AttestationData{
			Type: pluginName,
			Data: data,
		},
		SpiffeId: claims.AgentID(config.trustDomain),
	})
}

func (p *MSIAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config := new(MSIAttestorConfig)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, msiError.New("unable to decode configuration: %v", err)
	}

	if req.GlobalConfig == nil {
		return nil, msiError.New("global configuration is required")
	}
	if req.GlobalConfig.TrustDomain == "" {
		return nil, msiError.New("global configuration missing trust domain")
	}
	config.trustDomain = req.GlobalConfig.TrustDomain

	if config.ResourceID == "" {
		config.ResourceID = azure.DefaultMSIResourceID
	}

	p.setConfig(config)
	return &spi.ConfigureResponse{}, nil
}

func (p *MSIAttestorPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *MSIAttestorPlugin) getConfig() (*MSIAttestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, msiError.New("not configured")
	}
	return p.config, nil
}

func (p *MSIAttestorPlugin) setConfig(config *MSIAttestorConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = config
}

func getUnverifiedMSITokenClaims(rawToken string) (*azure.MSITokenClaims, error) {
	token, err := jwt.ParseSigned(rawToken)
	if err != nil {
		return nil, msiError.New("unable to parse token: %v", err)
	}

	claims := new(azure.MSITokenClaims)
	if err := token.UnsafeClaimsWithoutVerification(claims); err != nil {
		return nil, msiError.New("unable to parse token claims: %v", err)
	}

	if claims.Subject == "" {
		return nil, msiError.New("token missing subject claim")
	}
	if claims.TenantID == "" {
		return nil, msiError.New("token missing tenant ID claim")
	}

	return claims, nil
}
