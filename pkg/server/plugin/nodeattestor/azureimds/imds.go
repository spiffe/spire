package azureimds

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/azure"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	nodeattestorbase "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/base"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "azure_imds"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *IMDSAttestorPlugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type SecretAuthConfig struct {
	AppID     string `hcl:"app_id" json:"app_id"`
	AppSecret string `hcl:"app_secret" json:"app_secret"`
}

type TokenAuthConfig struct {
	TokenPath string `hcl:"token_path" json:"token_path"`
	AppID     string `hcl:"app_id" json:"app_id"`
}

type TenantConfig struct {
	AuthType                string            `hcl:"auth_type" json:"auth_type"`
	SecretAuth              *SecretAuthConfig `hcl:"secret_auth" json:"secret_auth"`
	TokenAuth               *TokenAuthConfig  `hcl:"token_auth" json:"token_auth"`
	AllowedTags             []string          `hcl:"allowed_vm_tags" json:"allowed_vm_tags"`
	RestrictToSubscriptions []*string         `hcl:"restrict_to_subscriptions" json:"restrict_to_subscriptions"`
}

type IMDSAttestorConfig struct {
	Tenants           map[string]*TenantConfig `hcl:"tenants" json:"tenants"`
	AgentPathTemplate string                   `hcl:"agent_path_template" json:"agent_path_template"`
}

type tenantConfig struct {
	client                  apiClient
	allowedTags             map[string]struct{}
	restrictToSubscriptions map[string]struct{}
}

type imdsAttestorConfig struct {
	td             spiffeid.TrustDomain
	tenants        map[string]*tenantConfig
	idPathTemplate *agentpathtemplate.Template
}

func (t *tenantConfig) subscriptionAllowed(subscriptionID string) bool {
	if len(t.restrictToSubscriptions) == 0 {
		return true
	}
	_, ok := t.restrictToSubscriptions[subscriptionID]
	return ok
}

func (p *IMDSAttestorPlugin) buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *imdsAttestorConfig {
	newConfig := new(IMDSAttestorConfig)

	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	if len(newConfig.Tenants) == 0 {
		status.ReportError("configuration must have at least one tenant")
	}

	tenants := make(map[string]*tenantConfig)
	for tenantDomain, tenant := range newConfig.Tenants {
		var client apiClient
		tenantID, err := p.hooks.lookupTenantID(tenantDomain)
		if err != nil {
			status.ReportErrorf("unable to lookup tenant ID: %v", err)
		}

		p.hooks.tenantIdMap[tenantDomain] = tenantID

		// Use tenant-specific credentials for resolving selectors
		switch {
		case tenant.SecretAuth != nil && tenant.TokenAuth != nil:
			status.ReportErrorf("misconfigured tenant %q: only one of secret_auth or token_auth may be specified in the config", tenantID)
		case tenant.TokenAuth != nil:
			if tenant.TokenAuth.TokenPath == "" {
				status.ReportErrorf("misconfigured tenant %q: missing token file path", tenantID)
			}
			if tenant.TokenAuth.AppID == "" {
				status.ReportErrorf("misconfigured tenant %q: missing app id", tenantID)
			}

			assertFunc := getAzureAssertionFunc(tenant.TokenAuth.TokenPath, os.ReadFile)
			cred, err := azidentity.NewClientAssertionCredential(tenantID, tenant.TokenAuth.AppID, assertFunc, nil)
			if err != nil {
				status.ReportErrorf("unable to get tenant client credential: %v", err)
			}

			client, err = p.hooks.newClient(cred)
			if err != nil {
				status.ReportErrorf("unable to create client for tenant %q: %v", tenantID, err)
			}
		case tenant.SecretAuth != nil:
			if tenant.SecretAuth.AppID == "" {
				status.ReportErrorf("misconfigured tenant %q: missing app id", tenantID)
			}
			if tenant.SecretAuth.AppSecret == "" {
				status.ReportErrorf("misconfigured tenant %q: missing app id", tenantID)
			}

			cred, err := azidentity.NewClientSecretCredential(tenantID, tenant.SecretAuth.AppID, tenant.SecretAuth.AppSecret, nil)
			if err != nil {
				status.ReportErrorf("unable to get tenant client credential: %v", err)
			}

			client, err = p.hooks.newClient(cred)
			if err != nil {
				status.ReportErrorf("unable to create client for tenant %q: %v", tenantID, err)
			}

		default:
			cred, err := p.hooks.fetchCredential(tenantID)
			if err != nil {
				status.ReportErrorf("unable to fetch client credential: %v", err)
			}
			client, err = p.hooks.newClient(cred)
			if err != nil {
				status.ReportErrorf("unable to create client with default credential: %v", err)
			}
		}

		// If credentials are not configured then selectors won't be gathered.
		if client == nil {
			status.ReportErrorf("no client credentials available for tenant %q", tenantID)
		}

		allowedTags := make(map[string]struct{})
		for _, tag := range tenant.AllowedTags {
			allowedTags[tag] = struct{}{}
		}

		restrictToSubscriptions := make(map[string]struct{})
		for _, subscription := range tenant.RestrictToSubscriptions {
			if subscription == nil {
				status.ReportErrorf("misconfigured tenant %q: restrict_to_subscriptions entries must be non-empty", tenantID)
				continue
			}
			value := strings.TrimSpace(*subscription)
			if value == "" {
				status.ReportErrorf("misconfigured tenant %q: restrict_to_subscriptions entries must be non-empty", tenantID)
				continue
			}
			restrictToSubscriptions[value] = struct{}{}
		}

		tenants[tenantDomain] = &tenantConfig{
			restrictToSubscriptions: restrictToSubscriptions,
			allowedTags:             allowedTags,
			client:                  client,
		}
	}

	tmpl := azure.DefaultIMDSAgentPathTemplate
	if len(newConfig.AgentPathTemplate) > 0 {
		var err error
		tmpl, err = agentpathtemplate.Parse(newConfig.AgentPathTemplate)
		if err != nil {
			status.ReportErrorf("failed to parse agent path template: %q", newConfig.AgentPathTemplate)
		}
	}

	return &imdsAttestorConfig{
		td:             coreConfig.TrustDomain,
		tenants:        tenants,
		idPathTemplate: tmpl,
	}
}

type IMDSAttestorPlugin struct {
	nodeattestorbase.Base
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	log hclog.Logger

	mu     sync.RWMutex
	config *imdsAttestorConfig

	hooks struct {
		tenantIdMap         map[string]string
		newClient           func(azcore.TokenCredential) (apiClient, error)
		fetchCredential     func(string) (azcore.TokenCredential, error)
		validateAttestedDoc func(context.Context, *azure.AttestedDocument) (*azure.AttestedDocumentContent, error)
		lookupTenantID      func(string) (string, error)
	}
}

var _ nodeattestorv1.NodeAttestorServer = (*IMDSAttestorPlugin)(nil)

func New() *IMDSAttestorPlugin {
	p := &IMDSAttestorPlugin{}
	p.hooks.tenantIdMap = make(map[string]string)
	p.hooks.newClient = newAzureClient
	p.hooks.fetchCredential = func(tenantID string) (azcore.TokenCredential, error) {
		return azidentity.NewDefaultAzureCredential(
			&azidentity.DefaultAzureCredentialOptions{
				TenantID: tenantID,
			},
		)
	}
	p.hooks.validateAttestedDoc = validateAttestedDocument
	p.hooks.lookupTenantID = lookupTenantID

	return p
}

func (p *IMDSAttestorPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *IMDSAttestorPlugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	// receive initial empty payload
	if _, err := stream.Recv(); err != nil {
		p.log.Info("received initial empty payload", "error", err)
		return err
	}

	config, err := p.getConfig()
	if err != nil {
		return err
	}

	// create a 32byte nonce
	nonce, err := generateRandomAlphanumeric(32)
	if err != nil {
		return err
	}

	// send nonce back to agent
	if err := stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{
			Challenge: []byte(nonce),
		},
	}); err != nil {
		return err
	}

	// receive the attestation payload
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	// Get the challenge response which contains the attested document and metadata
	payload := req.GetChallengeResponse()
	if payload == nil {
		return status.Error(codes.InvalidArgument, "missing attestation payload")
	}

	attestationData := new(azure.IMDSAttestationPayload)
	if err := json.Unmarshal(payload, attestationData); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to unmarshal data payload: %v", err)
	}

	// parse the document
	docData, err := p.hooks.validateAttestedDoc(stream.Context(), &attestationData.Document)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to validate attested document: %v", err)
	}

	validationError := validateUUID(docData.VMID)
	switch {
	case docData.VMID == "":
		return status.Errorf(codes.InvalidArgument, "missing VM ID in attested document")
	case docData.SubscriptionID == "":
		return status.Errorf(codes.InvalidArgument, "missing subscription ID in attested document")
	case docData.Nonce != nonce:
		return status.Errorf(codes.InvalidArgument, "nonce mismatch")
	case validationError != nil:
		return status.Errorf(codes.InvalidArgument, "invalid VM ID: %v", validationError)
	}

	untrustedMetadata := attestationData.Metadata

	// if the query hint has a domain look up the tenant id
	tenantID, ok := p.hooks.tenantIdMap[untrustedMetadata.AgentDomain]
	if !ok {
		return status.Errorf(codes.PermissionDenied, "tenant %q is not authorized", untrustedMetadata.AgentDomain)
	}
	docData.TenantID = tenantID

	tenant, ok := config.tenants[untrustedMetadata.AgentDomain]
	if !ok {
		return status.Errorf(codes.PermissionDenied, "tenant %q is not authorized", untrustedMetadata.AgentDomain)
	}

	if !tenant.subscriptionAllowed(docData.SubscriptionID) {
		return status.Errorf(codes.PermissionDenied, "subscription %q is not authorized", docData.SubscriptionID)
	}

	// Before doing the work to validate the token, ensure that the vmID has not already been used.
	agentID, err := azure.MakeIMDSAgentID(config.td, config.idPathTemplate, docData)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to make agent ID: %v", err)
	}

	if err := p.AssessTOFU(stream.Context(), agentID.String(), p.log); err != nil {
		return err
	}

	var selectorValues []string
	selectorValues, err = buildSelectors(stream.Context(), tenant, untrustedMetadata.VMSSName, docData.VMID, docData.SubscriptionID)
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

func (p *IMDSAttestorPlugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, p.buildConfig)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = newConfig

	return &configv1.ConfigureResponse{}, nil
}

func (p *IMDSAttestorPlugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, p.buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

func (p *IMDSAttestorPlugin) getConfig() (*imdsAttestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}
func buildSelectors(ctx context.Context, tenant *tenantConfig, vmssName *string, vmID string, subscriptionID string) ([]string, error) {
	client := tenant.client
	// build up a unique map of selectors. this is easier than deduping
	// individual selectors (e.g. the virtual network for each interface)
	selectorMap := map[string]bool{}
	// Get the VMSS Instance or Virtual Machine
	var (
		vm  *VirtualMachine
		err error
	)

	switch {
	case vmssName != nil:
		vm, err = client.GetVMSSInstance(ctx, vmID, subscriptionID, *vmssName)
		if err != nil {
			return nil, err
		}
		selectorMap[selectorValue("vmss-name", *vmssName)] = true
	default:
		vm, err = client.GetVirtualMachine(ctx, vmID, &subscriptionID)
		if err != nil {
			return nil, err
		}
	}

	selectorMap[selectorValue("subscription-id", subscriptionID)] = true
	selectorMap[selectorValue("vm-name", vm.Name)] = true
	selectorMap[selectorValue("vm-location", vm.Location)] = true
	selectorMap[selectorValue("resource-group", vm.ResourceGroup)] = true

	// add tag selectors
	if vm.Tags != nil {
		for tag := range tenant.allowedTags {
			if value, ok := vm.Tags[tag]; ok && value != nil {
				var v string
				if iv, ok := value.(*string); ok {
					v = *iv
				} else {
					v = value.(string)
				}
				selectorMap[selectorValue("vm-tag", tag, v)] = true
			}
		}
	}

	// add network interface selectors
	for _, networkInterface := range vm.Interfaces {
		selectorMap[selectorValue("network-security-group", networkInterface.SecurityGroup.ResourceGroup, networkInterface.SecurityGroup.Name)] = true
		for _, subnet := range networkInterface.Subnets {
			selectorMap[selectorValue("virtual-network", subnet.VNet)] = true
			selectorMap[selectorValue("virtual-network-subnet", subnet.VNet, subnet.SubnetName)] = true
		}
	}

	// sort and return selectors
	selectorValues := make([]string, 0, len(selectorMap))
	for selectorValue := range selectorMap {
		selectorValues = append(selectorValues, selectorValue)
	}
	sort.Strings(selectorValues)
	return selectorValues, nil
}
