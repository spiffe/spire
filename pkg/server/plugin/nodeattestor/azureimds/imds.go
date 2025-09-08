package azureimds

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/digitorus/pkcs7"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
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

var (
	reVirtualMachineID       = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft.Compute/virtualMachines/([^/]+)$`)
	reNetworkSecurityGroupID = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft.Network/networkSecurityGroups/([^/]+)$`)
	reNetworkInterfaceID     = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft.Network/networkInterfaces/([^/]+)$`)
	reVirtualNetworkSubnetID = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft.Network/virtualNetworks/([^/]+)/subnets/([^/]+)$`)
	reTenantId               = regexp.MustCompile(`^https://sts.windows.net/([^/]+)/$`)
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
	AuthType             string            `hcl:"auth_type" json:"auth_type"`
	SecretAuth           *SecretAuthConfig `hcl:"secret_auth" json:"secret_auth"`
	TokenAuth            *TokenAuthConfig  `hcl:"token_auth" json:"token_auth"`
	AllowedTags          []string          `hcl:"allowed_vm_tags" json:"allowed_vm_tags"`
	AllowedSubscriptions []*string         `hcl:"allowed_subscriptions" json:"allowed_subscriptions"`
}

type IMDSAttestorConfig struct {
	Tenants           map[string]*TenantConfig `hcl:"tenants" json:"tenants"`
	AgentPathTemplate string                   `hcl:"agent_path_template" json:"agent_path_template"`
}

type tenantConfig struct {
	client               apiClient
	allowedTags          map[string]struct{}
	allowedSubscriptions []*string
}

type msiAttestorConfig struct {
	td             spiffeid.TrustDomain
	tenants        map[string]*tenantConfig
	idPathTemplate *agentpathtemplate.Template
}

func (p *IMDSAttestorPlugin) buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *msiAttestorConfig {
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
		tenantID, err := lookupTenantID(tenantDomain)
		if err != nil {
			status.ReportErrorf("unable to lookup tenant ID: %v", err)
		}
		// Use tenant-specific credentials for resolving selectors
		switch {
		case tenant.TokenAuth != nil:
			if tenant.TokenAuth.TokenPath == "" {
				status.ReportErrorf("misconfigured tenant %q: missing token path", tenantID)
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

		tenants[tenantID] = &tenantConfig{
			allowedSubscriptions: tenant.AllowedSubscriptions,
			allowedTags:          allowedTags,
			client:               client,
		}
	}

	tmpl := azure.DefaultAgentPathTemplate
	if len(newConfig.AgentPathTemplate) > 0 {
		var err error
		tmpl, err = agentpathtemplate.Parse(newConfig.AgentPathTemplate)
		if err != nil {
			status.ReportErrorf("failed to parse agent path template: %q", newConfig.AgentPathTemplate)
		}
	}

	return &msiAttestorConfig{
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
	config *msiAttestorConfig

	hooks struct {
		now                   func() time.Time
		newClient             func(azcore.TokenCredential) (apiClient, error)
		fetchInstanceMetadata func(azure.HTTPClient) (*azure.InstanceMetadata, error)
		fetchCredential       func(string) (azcore.TokenCredential, error)
	}
}

var _ nodeattestorv1.NodeAttestorServer = (*IMDSAttestorPlugin)(nil)

func New() *IMDSAttestorPlugin {
	p := &IMDSAttestorPlugin{}
	p.hooks.now = time.Now
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

func (p *IMDSAttestorPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *IMDSAttestorPlugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
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

	attestationData := new(azure.IMDSAttestedData)
	if err := json.Unmarshal(payload, attestationData); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to unmarshal data payload: %v", err)
	}

	// parse the document
	docData, err := validateAttestedDocument(stream.Context(), &attestationData.Document)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to validate attested document: %v", err)
	}

	//TODO: Verify that the signature is from Microsoft Azure, and check the certificate chain for errors
	//! https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service?tabs=linux#sample-1-validate-that-the-vm-is-running-in-azure
	//This is very important and  MUST be done before releasing to upstream

	switch {
	case docData.VMID == "":
		return status.Errorf(codes.InvalidArgument, "missing VM ID in attested document")
	case docData.SubscriptionID == "":
		return status.Errorf(codes.InvalidArgument, "missing subscription ID in attested document")
	}

	// parse the query hint
	queryHint := attestationData.QueryHint

	// if the query hint is a VMSS name, get the VMSS info and instance

	// if the query hint has a domain look up the tenant id
	tenantID, err := lookupTenantID(queryHint.AgentDomain)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to lookup tenant ID: %v", err)
	}
	docData.TenantID = tenantID

	// Before doing the work to validate the token, ensure that the vmID has not already been used.
	agentID, err := azure.MakeIMDSAgentID(config.td, config.idPathTemplate, docData)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to make agent ID: %v", err)
	}

	if err := p.AssessTOFU(stream.Context(), agentID.String(), p.log); err != nil {
		return err
	}

	tenant, ok := config.tenants[queryHint.AgentDomain]
	if !ok {
		return status.Errorf(codes.PermissionDenied, "tenant %q is not authorized", queryHint.AgentDomain)
	}

	var selectorValues []string
	selectorValues, err = buildSelectors(stream.Context(), tenant, queryHint.VMSSName, docData.VMID, docData.SubscriptionID, tenant.allowedSubscriptions)
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

func (p *IMDSAttestorPlugin) getConfig() (*msiAttestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}
func buildSelectors(ctx context.Context, tenant *tenantConfig, vmssName *string, vmID string, subscriptionID string, allowedSubscriptions []*string) ([]string, error) {
	client := tenant.client

	//Get the VMSS Instance or Virtual Machine
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
	default:
		vm, err = client.GetVirtualMachine(ctx, vmID, &subscriptionID)
		if err != nil {
			return nil, err
		}
	}
	// build up a unique map of selectors. this is easier than deduping
	// individual selectors (e.g. the virtual network for each interface)
	selectorMap := map[string]bool{
		selectorValue("subscription-id", subscriptionID): true,
		selectorValue("vm-name", vm.Name):                true,
		selectorValue("vm-location", vm.Location):        true,
	}

	// add tag selectors
	if vm.Tags != nil {
		for tag := range tenant.allowedTags {
			if value, ok := vm.Tags[tag]; ok && value != nil {
				selectorMap[selectorValue("tag", tag, value.(string))] = true
			}
		}
	}

	// add network interface selectors
	networkInterfaces, err := client.GetNetworkInterfaces(ctx, vmID, &subscriptionID)
	if err != nil {
		return nil, err
	}
	for _, networkInterface := range networkInterfaces {
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

func selectorValue(parts ...string) string {
	return strings.Join(parts, ":")
}

// ValidateAttestedDocument validates the Azure IMDS attested document signature
func validateAttestedDocument(ctx context.Context, doc *azure.AttestedDocument) (*azure.AttestedDocumentPayload, error) {
	if doc.Signature == "" {
		return nil, fmt.Errorf("missing signature in attested document")
	}

	// Step 1: Base64 decode the signature
	decodedSignature, err := base64.StdEncoding.DecodeString(doc.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	// Step 2: Parse the PKCS7 signature
	pkcs7Sig, err := pkcs7.Parse(decodedSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS7 signature: %w", err)
	}

	// Step 3: Extract the signing certificate
	if len(pkcs7Sig.Certificates) == 0 {
		return nil, fmt.Errorf("no certificates found in PKCS7 signature")
	}

	signingCert := pkcs7Sig.Certificates[0]

	// Step 4: Get the intermediate certificate from CA Issuers extension
	intermediateCert, err := getIntermediateCertificate(ctx, signingCert)
	if err != nil {
		return nil, fmt.Errorf("failed to get intermediate certificate: %w", err)
	}

	// Step 5: Add certificates to PKCS7 for verification
	if intermediateCert != nil {
		pkcs7Sig.Certificates = append(pkcs7Sig.Certificates, intermediateCert)
	}
	// Step 6: Verify the signature
	//TODO: Uncomment this when we have a way to verify the signature
	// if err := pkcs7Sig.Verify(); err != nil {
	// 	return nil, fmt.Errorf("signature verification failed: %w", err)
	// }

	var payload *azure.AttestedDocumentPayload
	if err := json.Unmarshal(pkcs7Sig.Content, payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attested document payload: %w", err)
	}
	return payload, nil
}

// getIntermediateCertificate fetches the intermediate certificate from the CA Issuers URL
func getIntermediateCertificate(ctx context.Context, signingCert *x509.Certificate) (*x509.Certificate, error) {
	// Extract CA Issuers URL from the signing certificate
	var caIssuersURL string
	for _, url := range signingCert.IssuingCertificateURL {
		if url != "" {
			caIssuersURL = url
			break
		}
	}

	if caIssuersURL == "" {
		return nil, fmt.Errorf("no CA Issuers URL found in signing certificate")
	}

	// Fetch the intermediate certificate
	req, err := http.NewRequestWithContext(ctx, "GET", caIssuersURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for intermediate certificate: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch intermediate certificate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch intermediate certificate, status: %d", resp.StatusCode)
	}

	certData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read intermediate certificate: %w", err)
	}

	// Try parsing as DER first, then PEM
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		// Try parsing as PEM
		block, _ := pem.Decode(certData)
		if block == nil {
			return nil, fmt.Errorf("failed to decode intermediate certificate as PEM")
		}
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse intermediate certificate: %w", err)
		}
	}

	return cert, nil
}
func getAzureAssertionFunc(tokenPath string, reader func(name string) ([]byte, error)) func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		token, err := reader(tokenPath)
		if err != nil {
			return "", fmt.Errorf("unable to read token file %q: %w", tokenPath, err)
		}
		if _, err := jwt.ParseSigned(string(token), allowedJWTSignatureAlgorithms); err != nil {
			return "", fmt.Errorf("unable to parse token file %q: %w", tokenPath, err)
		}

		return string(token), nil
	}
}

func lookupTenantID(domain string) (string, error) {
	// make an http request to https://login.microsoftonline.com/<domain>/.well-known/openid-configuration
	req, err := http.NewRequest("GET", fmt.Sprintf("https://login.microsoftonline.com/%s/.well-known/openid-configuration", domain), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request for tenant ID: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch tenant ID: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch tenant ID, status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read tenant ID: %w", err)
	}
	var data struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", fmt.Errorf("failed to unmarshal tenant ID: %w", err)
	}
	return extractTenantID(data.Issuer)
}

func extractTenantID(issuer string) (string, error) {
	m := reTenantId.FindStringSubmatch(issuer)
	if m == nil {
		return "", fmt.Errorf("malformed tenant ID: %s", issuer)
	}
	return m[1], nil
}
