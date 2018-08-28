package azure

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/jwtutil"
	"github.com/spiffe/spire/pkg/common/plugin/azure"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/zeebo/errs"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	pluginName = "azure_msi"

	// MSI tokens have the not-before ("nbf") claim. If there are clock
	// differences between the agent and server then token validation may fail
	// unless we give a little leeway. Tokens are valid for 8 hours, so a few
	// minutes extra in that direction does not seem like a big deal.
	tokenLeeway = time.Minute * 5

	keySetRefreshInterval = time.Hour
	azureOIDCIssuer       = "https://login.microsoftonline.com/common/"
)

var (
	msiError = errs.Class("azure-msi")
)

type TenantConfig struct {
	ResourceID string `hcl:"resource_id"`
}

type MSIAttestorConfig struct {
	trustDomain string
	Tenants     map[string]*TenantConfig `hcl:"tenants"`
}

type MSIAttestorPlugin struct {
	mu     sync.RWMutex
	config *MSIAttestorConfig

	hooks struct {
		now            func() time.Time
		keySetProvider jwtutil.KeySetProvider
	}
}

var _ nodeattestor.Plugin = (*MSIAttestorPlugin)(nil)

func NewMSIAttestorPlugin() *MSIAttestorPlugin {
	p := &MSIAttestorPlugin{}
	p.hooks.now = time.Now
	p.hooks.keySetProvider = jwtutil.NewCachingKeySetProvider(jwtutil.OIDCIssuer(azureOIDCIssuer), keySetRefreshInterval)
	return p
}

func (p *MSIAttestorPlugin) Attest(stream nodeattestor.Attest_PluginStream) error {
	req, err := stream.Recv()
	if err != nil {
		return msiError.Wrap(err)
	}

	config, err := p.getConfig()
	if err != nil {
		return err
	}

	if req.AttestedBefore {
		return msiError.New("node has already attested")
	}

	if req.AttestationData == nil {
		return msiError.New("missing attestation data")
	}

	if dataType := req.AttestationData.Type; dataType != pluginName {
		return msiError.New("unexpected attestation data type %q", dataType)
	}

	if req.AttestationData.Data == nil {
		return msiError.New("missing attestation data payload")
	}

	attestationData := new(azure.MSIAttestationData)
	if err := json.Unmarshal(req.AttestationData.Data, attestationData); err != nil {
		return msiError.New("failed to unmarshal data payload: %v", err)
	}

	if attestationData.Token == "" {
		return msiError.New("missing token from attestation data")
	}

	keySet, err := p.hooks.keySetProvider.GetKeySet(stream.Context())
	if err != nil {
		return msiError.New("unable to obtain JWKS: %v", err)
	}

	token, err := jwt.ParseSigned(attestationData.Token)
	if err != nil {
		return msiError.New("unable to parse token: %v", err)
	}

	keyID, ok := getTokenKeyID(token)
	if !ok {
		return msiError.New("token missing key id")
	}

	keys := keySet.Key(keyID)
	if len(keys) == 0 {
		return msiError.New("key id %q not found", keyID)
	}

	claims := new(azure.MSITokenClaims)
	if err := token.Claims(&keys[0], claims); err != nil {
		return msiError.New("unable to verify token: %v", err)
	}

	// make sure tenant id is present and authorized
	if claims.TenantID == "" {
		return msiError.New("token missing tenant ID claim")
	}
	tenant, ok := config.Tenants[claims.TenantID]
	if !ok {
		return msiError.New("tenant %q is not authorized", claims.TenantID)
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Audience: []string{tenant.ResourceID},
		Time:     p.hooks.now(),
	}, tokenLeeway); err != nil {
		return msiError.New("unable to validate token claims: %v", err)
	}

	// make sure principal id is in subject claim
	if claims.Subject == "" {
		return msiError.New("token missing subject claim")
	}

	return stream.Send(&nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: claims.AgentID(config.trustDomain),
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

	if len(config.Tenants) == 0 {
		return nil, msiError.New("configuration must have at least one tenant")
	}
	for _, tenant := range config.Tenants {
		if tenant.ResourceID == "" {
			tenant.ResourceID = azure.DefaultMSIResourceID
		}
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

func getTokenKeyID(token *jwt.JSONWebToken) (string, bool) {
	for _, h := range token.Headers {
		if h.KeyID != "" {
			return h.KeyID, true
		}
	}
	return "", false
}
