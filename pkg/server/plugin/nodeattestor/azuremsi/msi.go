package azuremsi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/jwtutil"
	"github.com/spiffe/spire/pkg/common/plugin/azure"
	nodeattestorbase "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/base"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	reVirtualMachineID       = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft.Compute/virtualMachines/([^/]+)$`)
	reNetworkSecurityGroupID = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft.Network/networkSecurityGroups/([^/]+)$`)
	reNetworkInterfaceID     = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft.Network/networkInterfaces/([^/]+)$`)
	reVirtualNetworkSubnetID = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft.Network/virtualNetworks/([^/]+)/subnets/([^/]+)$`)
	// Azure doesn't appear to publicly document which signature algorithms they use for MSI tokens,
	// but a couple examples online were showing RS256.
	// To ensure compatibility, accept the most common signature algorithms that are known to be secure.
	allowedJWTSignatureAlgorithms = []jose.SignatureAlgorithm{
		jose.RS256,
		jose.RS384,
		jose.RS512,
		jose.ES256,
		jose.ES384,
		jose.ES512,
		jose.PS256,
		jose.PS384,
		jose.PS512,
	}
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
	ResourceID     string `hcl:"resource_id" json:"resource_id"`
	SubscriptionID string `hcl:"subscription_id" json:"subscription_id"`
	AppID          string `hcl:"app_id" json:"app_id"`
	AppSecret      string `hcl:"app_secret" json:"app_secret"`

	// Deprecated: use_msi is deprecated and will be removed in a future release.
	// Will be used implicitly if other mechanisms to authenticate fail.
	UseMSI bool `hcl:"use_msi" json:"use_msi"`
}

type MSIAttestorConfig struct {
	Tenants           map[string]*TenantConfig `hcl:"tenants" json:"tenants"`
	AgentPathTemplate string                   `hcl:"agent_path_template" json:"agent_path_template"`
}

type tenantConfig struct {
	resourceID string
	client     apiClient
}

type msiAttestorConfig struct {
	td             spiffeid.TrustDomain
	tenants        map[string]*tenantConfig
	idPathTemplate *agentpathtemplate.Template
}

type MSIAttestorPlugin struct {
	nodeattestorbase.Base
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	log hclog.Logger

	mu     sync.RWMutex
	config *msiAttestorConfig

	hooks struct {
		now                   func() time.Time
		keySetProvider        jwtutil.KeySetProvider
		newClient             func(string, azcore.TokenCredential) (apiClient, error)
		fetchInstanceMetadata func(azure.HTTPClient) (*azure.InstanceMetadata, error)
		fetchCredential       func(string) (azcore.TokenCredential, error)
	}
}

var _ nodeattestorv1.NodeAttestorServer = (*MSIAttestorPlugin)(nil)

func New() *MSIAttestorPlugin {
	p := &MSIAttestorPlugin{}
	p.hooks.now = time.Now
	p.hooks.keySetProvider = jwtutil.NewCachingKeySetProvider(jwtutil.OIDCIssuer(azureOIDCIssuer), keySetRefreshInterval)
	p.hooks.newClient = newAzureClient
	p.hooks.fetchInstanceMetadata = azure.FetchInstanceMetadata
	p.hooks.fetchCredential = func(tenantID string) (azcore.TokenCredential, error) {
		return azidentity.NewDefaultAzureCredential(
			&azidentity.DefaultAzureCredentialOptions{
				TenantID: tenantID,
			},
		)
	}

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

	token, err := jwt.ParseSigned(attestationData.Token, allowedJWTSignatureAlgorithms)
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

	switch {
	case claims.TenantID == "":
		return status.Error(codes.Internal, "token missing tenant ID claim")
	case claims.PrincipalID == "":
		return status.Error(codes.Internal, "token missing subject claim")
	}

	// Before doing the work to validate the token, ensure that this MSI token
	// has not already been used to attest an agent.
	agentID, err := azure.MakeAgentID(config.td, config.idPathTemplate, claims)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to make agent ID: %v", err)
	}

	if err := p.AssessTOFU(stream.Context(), agentID.String(), p.log); err != nil {
		return err
	}

	tenant, ok := config.tenants[claims.TenantID]
	if !ok {
		return status.Errorf(codes.PermissionDenied, "tenant %q is not authorized", claims.TenantID)
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		AnyAudience: []string{tenant.resourceID},
		Time:        p.hooks.now(),
	}, tokenLeeway); err != nil {
		return status.Errorf(codes.Internal, "unable to validate token claims: %v", err)
	}

	var selectorValues []string
	selectorValues, err = p.resolve(stream.Context(), tenant.client, claims.PrincipalID)
	if err != nil {
		return err
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       agentID.String(),
				CanReattest:    false,
				SelectorValues: selectorValues,
			},
		},
	})
}

func (p *MSIAttestorPlugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
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

	if len(hclConfig.Tenants) == 0 {
		return nil, status.Error(codes.InvalidArgument, "configuration must have at least one tenant")
	}
	for _, tenant := range hclConfig.Tenants {
		if tenant.ResourceID == "" {
			tenant.ResourceID = azure.DefaultMSIResourceID
		}
	}

	td, err := spiffeid.TrustDomainFromString(req.CoreConfiguration.TrustDomain)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	tenants := make(map[string]*tenantConfig)

	for tenantID, tenant := range hclConfig.Tenants {
		var client apiClient

		// Use tenant-specific credentials for resolving selectors
		switch {
		case tenant.SubscriptionID != "", tenant.AppID != "", tenant.AppSecret != "":
			if tenant.UseMSI {
				return nil, status.Errorf(codes.InvalidArgument, "misconfigured tenant %q: cannot use both MSI and app authentication", tenantID)
			}
			if tenant.SubscriptionID == "" {
				return nil, status.Errorf(codes.InvalidArgument, "misconfigured tenant %q: missing subscription id", tenantID)
			}
			if tenant.AppID == "" {
				return nil, status.Errorf(codes.InvalidArgument, "misconfigured tenant %q: missing app id", tenantID)
			}
			if tenant.AppSecret == "" {
				return nil, status.Errorf(codes.InvalidArgument, "misconfigured tenant %q: missing app secret", tenantID)
			}

			cred, err := azidentity.NewClientSecretCredential(tenantID, tenant.AppID, tenant.AppSecret, nil)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "unable to get tenant client credential: %v", err)
			}

			client, err = p.hooks.newClient(tenant.SubscriptionID, cred)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "unable to create client for tenant %q: %v", tenantID, err)
			}

		case tenant.UseMSI:
			p.log.Warn("use_msi is deprecated and will be removed in a future release")
			fallthrough // use default credential which attempts to fetch credentials using MSI

		default:
			instanceMetadata, err := p.hooks.fetchInstanceMetadata(http.DefaultClient)
			if err != nil {
				return nil, err
			}
			cred, err := p.hooks.fetchCredential(tenantID)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "unable to fetch client credential: %v", err)
			}
			client, err = p.hooks.newClient(instanceMetadata.Compute.SubscriptionID, cred)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "unable to create client with default credential: %v", err)
			}
		}

		// If credentials are not configured then selectors won't be gathered.
		if client == nil {
			return nil, status.Errorf(codes.Internal, "no client credentials available for tenant %q", tenantID)
		}

		tenants[tenantID] = &tenantConfig{
			resourceID: tenant.ResourceID,
			client:     client,
		}
	}

	tmpl := azure.DefaultAgentPathTemplate
	if len(hclConfig.AgentPathTemplate) > 0 {
		var err error
		tmpl, err = agentpathtemplate.Parse(hclConfig.AgentPathTemplate)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to parse agent path template: %q", hclConfig.AgentPathTemplate)
		}
	}

	p.setConfig(&msiAttestorConfig{
		td:             td,
		tenants:        tenants,
		idPathTemplate: tmpl,
	})
	return &configv1.ConfigureResponse{}, nil
}

func (p *MSIAttestorPlugin) getConfig() (*msiAttestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func (p *MSIAttestorPlugin) setConfig(config *msiAttestorConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = config
}

func (p *MSIAttestorPlugin) resolve(ctx context.Context, client apiClient, principalID string) ([]string, error) {
	// Retrieve the resource belonging to the principal id.
	vmResourceID, err := client.GetVirtualMachineResourceID(ctx, principalID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to get resource for principal %q: %v", principalID, err)
	}

	// parse out the resource group and vm name from the resource ID
	vmResourceGroup, vmName, err := parseVirtualMachineID(vmResourceID)
	if err != nil {
		return nil, err
	}

	// build up a unique map of selectors. this is easier than deduping
	// individual selectors (e.g. the virtual network for each interface)
	selectorMap := map[string]bool{
		selectorValue("subscription-id", client.SubscriptionID()): true,
		selectorValue("vm-name", vmResourceGroup, vmName):         true,
	}
	addSelectors := func(values []string) {
		for _, value := range values {
			selectorMap[value] = true
		}
	}

	// pull the VM information and gather selectors
	vm, err := client.GetVirtualMachine(ctx, vmResourceGroup, vmName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to get virtual machine %q: %v", resourceGroupName(vmResourceGroup, vmName), err)
	}
	if vm.Properties.NetworkProfile != nil {
		networkProfileSelectors, err := getNetworkProfileSelectors(ctx, client, vm.Properties.NetworkProfile)
		if err != nil {
			return nil, err
		}
		addSelectors(networkProfileSelectors)
	}

	// sort and return selectors
	selectorValues := make([]string, 0, len(selectorMap))
	for selectorValue := range selectorMap {
		selectorValues = append(selectorValues, selectorValue)
	}
	sort.Strings(selectorValues)

	return selectorValues, nil
}

func getNetworkProfileSelectors(ctx context.Context, client apiClient, networkProfile *armcompute.NetworkProfile) ([]string, error) {
	if networkProfile.NetworkInterfaces == nil {
		return nil, nil
	}

	var selectors []string
	for _, interfaceRef := range networkProfile.NetworkInterfaces {
		if interfaceRef.ID == nil {
			continue
		}
		niResourceGroup, niName, err := parseNetworkInterfaceID(*interfaceRef.ID)
		if err != nil {
			return nil, err
		}
		networkInterface, err := client.GetNetworkInterface(ctx, niResourceGroup, niName)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to get network interface %q: %v", resourceGroupName(niResourceGroup, niName), err)
		}

		networkInterfaceSelectors, err := getNetworkInterfaceSelectors(networkInterface)
		if err != nil {
			return nil, err
		}

		selectors = append(selectors, networkInterfaceSelectors...)
	}

	return selectors, nil
}

func getNetworkInterfaceSelectors(networkInterface *armnetwork.Interface) ([]string, error) {
	var selectors []string
	if nsg := networkInterface.Properties.NetworkSecurityGroup; nsg != nil && nsg.ID != nil {
		nsgResourceGroup, nsgName, err := parseNetworkSecurityGroupID(*nsg.ID)
		if err != nil {
			return nil, err
		}
		selectors = append(selectors, selectorValue("network-security-group", nsgResourceGroup, nsgName))
	}

	if ipcs := networkInterface.Properties.IPConfigurations; ipcs != nil {
		for _, ipc := range ipcs {
			if props := ipc.Properties; props != nil {
				if subnet := props.Subnet; subnet != nil && subnet.ID != nil {
					subResourceGroup, subVirtualNetwork, subName, err := parseVirtualNetworkSubnetID(*subnet.ID)
					if err != nil {
						return nil, err
					}
					selectors = append(selectors, selectorValue("virtual-network", subResourceGroup, subVirtualNetwork))
					selectors = append(selectors, selectorValue("virtual-network-subnet", subResourceGroup, subVirtualNetwork, subName))
				}
			}
		}
	}

	return selectors, nil
}

func parseVirtualMachineID(id string) (resourceGroup, name string, err error) {
	m := reVirtualMachineID.FindStringSubmatch(id)
	if m == nil {
		return "", "", status.Errorf(codes.Internal, "malformed virtual machine ID %q", id)
	}
	return m[1], m[2], nil
}

func parseNetworkSecurityGroupID(id string) (resourceGroup, name string, err error) {
	m := reNetworkSecurityGroupID.FindStringSubmatch(id)
	if m == nil {
		return "", "", status.Errorf(codes.Internal, "malformed network security group ID %q", id)
	}
	return m[1], m[2], nil
}

func parseNetworkInterfaceID(id string) (resourceGroup, name string, err error) {
	m := reNetworkInterfaceID.FindStringSubmatch(id)
	if m == nil {
		return "", "", status.Errorf(codes.Internal, "malformed network interface ID %q", id)
	}
	return m[1], m[2], nil
}

func parseVirtualNetworkSubnetID(id string) (resourceGroup, networkName, subnetName string, err error) {
	m := reVirtualNetworkSubnetID.FindStringSubmatch(id)
	if m == nil {
		return "", "", "", status.Errorf(codes.Internal, "malformed virtual network subnet ID %q", id)
	}
	return m[1], m[2], m[3], nil
}

func resourceGroupName(resourceGroup, name string) string {
	return fmt.Sprintf("%s:%s", resourceGroup, name)
}

func selectorValue(parts ...string) string {
	return strings.Join(parts, ":")
}

func getTokenKeyID(token *jwt.JSONWebToken) (string, bool) {
	for _, h := range token.Headers {
		if h.KeyID != "" {
			return h.KeyID, true
		}
	}
	return "", false
}
