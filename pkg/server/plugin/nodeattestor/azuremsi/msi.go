package azuremsi

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/jwtutil"
	"github.com/spiffe/spire/pkg/common/plugin/azure"
	nodeattestorbase "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/base"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *MSIAttestorPlugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type TenantConfig struct {
	ResourceID string `hcl:"resource_id"`
}

type MSIAttestorConfig struct {
	trustDomain string
	Tenants     map[string]*TenantConfig `hcl:"tenants"`
}

type MSIAttestorPlugin struct {
	nodeattestorbase.Base
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	log hclog.Logger

	mu     sync.RWMutex
	config *MSIAttestorConfig

	hooks struct {
		now            func() time.Time
		keySetProvider jwtutil.KeySetProvider
	}
}

var _ nodeattestorv1.NodeAttestorServer = (*MSIAttestorPlugin)(nil)

func New() *MSIAttestorPlugin {
	p := &MSIAttestorPlugin{}
	p.hooks.now = time.Now
	p.hooks.keySetProvider = jwtutil.NewCachingKeySetProvider(jwtutil.OIDCIssuer(azureOIDCIssuer), keySetRefreshInterval)
	return p
}

func (p *MSIAttestorPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *MSIAttestorPlugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	config, err := p.getConfig()
	if err != nil {
		return err
	}

	payload := req.GetPayload()
	if payload == nil {
		return status.Error(codes.InvalidArgument, "missing attestation payload")
	}

	attestationData := new(azure.MSIAttestationData)
	if err := json.Unmarshal(payload, attestationData); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to unmarshal data payload: %v", err)
	}

	if attestationData.Token == "" {
		return status.Errorf(codes.InvalidArgument, "missing token from attestation data")
	}

	keySet, err := p.hooks.keySetProvider.GetKeySet(stream.Context())
	if err != nil {
		return status.Errorf(codes.Internal, "unable to obtain JWKS: %v", err)
	}

	token, err := jwt.ParseSigned(attestationData.Token)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to parse token: %v", err)
	}

	keyID, ok := getTokenKeyID(token)
	if !ok {
		return status.Error(codes.InvalidArgument, "token missing key id")
	}

	keys := keySet.Key(keyID)
	if len(keys) == 0 {
		return status.Errorf(codes.InvalidArgument, "key id %q not found", keyID)
	}

	claims := new(azure.MSITokenClaims)
	if err := token.Claims(&keys[0], claims); err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to verify token: %v", err)
	}
	agentID := claims.AgentID(config.trustDomain)

	if err := p.AssessTOFU(stream.Context(), agentID, p.log); err != nil {
		return err
	}

	// make sure tenant id is present and authorized
	if claims.TenantID == "" {
		return status.Error(codes.Internal, "token missing tenant ID claim")
	}
	tenant, ok := config.Tenants[claims.TenantID]
	if !ok {
		return status.Errorf(codes.PermissionDenied, "tenant %q is not authorized", claims.TenantID)
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Audience: []string{tenant.ResourceID},
		Time:     p.hooks.now(),
	}, tokenLeeway); err != nil {
		return status.Errorf(codes.Internal, "unable to validate token claims: %v", err)
	}

	// make sure principal id is in subject claim
	if claims.Subject == "" {
		return status.Error(codes.Internal, "token missing subject claim")
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:    agentID,
				CanReattest: false,
			},
		},
	})
}

func (p *MSIAttestorPlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	hclConfig := new(MSIAttestorConfig)
	if err := hcl.Decode(hclConfig, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}
	if req.CoreConfiguration == nil {
		return nil, status.Error(codes.InvalidArgument, "core configuration is required")
	}
	if req.CoreConfiguration.TrustDomain == "" {
		return nil, status.Error(codes.InvalidArgument, "core configuration missing trust domain")
	}
	hclConfig.trustDomain = req.CoreConfiguration.TrustDomain

	if len(hclConfig.Tenants) == 0 {
		return nil, status.Error(codes.InvalidArgument, "configuration must have at least one tenant")
	}
	for _, tenant := range hclConfig.Tenants {
		if tenant.ResourceID == "" {
			tenant.ResourceID = azure.DefaultMSIResourceID
		}
	}

	p.setConfig(hclConfig)
	return &configv1.ConfigureResponse{}, nil
}

func (p *MSIAttestorPlugin) getConfig() (*MSIAttestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
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
