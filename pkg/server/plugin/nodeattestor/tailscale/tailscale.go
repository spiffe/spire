package tailscale

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/spiffe/spire/pkg/common/catalog"
	common "github.com/spiffe/spire/pkg/common/plugin/tailscale"
	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"github.com/spiffe/spire/pkg/common/util"
	nodeattestorbase "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/base"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "tailscale"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// Config is the HCL configuration for the plugin.
type Config struct {
	CABundlePath      string `hcl:"ca_bundle_path"`
	Tailnet           string `hcl:"tailnet"`
	APIKey            string `hcl:"api_key"`
	APIURL            string `hcl:"api_url"`
	AgentPathTemplate string `hcl:"agent_path_template"`
}

type configuration struct {
	trustDomain  spiffeid.TrustDomain
	trustBundle  *x509.CertPool
	tailnet      string
	apiKey       string
	apiURL       string
	pathTemplate *agentpathtemplate.Template
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *configuration {
	hclConfig := new(Config)
	if err := hcl.Decode(hclConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	if hclConfig.CABundlePath == "" {
		status.ReportError("ca_bundle_path is required")
	}

	if hclConfig.Tailnet == "" {
		status.ReportError("tailnet is required")
	}

	if hclConfig.APIKey == "" {
		status.ReportError("api_key is required")
	}

	var trustBundles []*x509.Certificate
	if hclConfig.CABundlePath != "" {
		certs, err := util.LoadCertificates(hclConfig.CABundlePath)
		if err != nil {
			status.ReportErrorf("unable to load trust bundle %q: %v", hclConfig.CABundlePath, err)
		}
		trustBundles = append(trustBundles, certs...)
	}

	pathTemplate := common.DefaultAgentPathTemplate
	if len(hclConfig.AgentPathTemplate) > 0 {
		tmpl, err := agentpathtemplate.Parse(hclConfig.AgentPathTemplate)
		if err != nil {
			status.ReportErrorf("failed to parse agent path template: %q", hclConfig.AgentPathTemplate)
		}
		pathTemplate = tmpl
	}

	return &configuration{
		trustDomain:  coreConfig.TrustDomain,
		trustBundle:  util.NewCertPool(trustBundles...),
		tailnet:      hclConfig.Tailnet,
		apiKey:       hclConfig.APIKey,
		apiURL:       hclConfig.APIURL,
		pathTemplate: pathTemplate,
	}
}

// Plugin implements the server-side Tailscale node attestor.
type Plugin struct {
	nodeattestorbase.Base
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	config *configuration
	mtx    sync.Mutex
	log    hclog.Logger
	hooks  struct {
		newClient func(apiKey, apiURL string) tailscaleClient
	}
}

func New() *Plugin {
	p := &Plugin{}
	p.hooks.newClient = func(apiKey, apiURL string) tailscaleClient {
		return newHTTPClient(apiKey, apiURL)
	}
	return p
}

// SetLogger sets the plugin logger.
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Attest implements the server-side node attestation flow.
func (p *Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	// Step 1: Receive payload
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	payload := req.GetPayload()
	if payload == nil {
		return status.Error(codes.InvalidArgument, "missing attestation payload")
	}

	// Step 2: Unmarshal attestation data
	attestationData := new(common.AttestationData)
	if err := json.Unmarshal(payload, attestationData); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to unmarshal data: %v", err)
	}

	// Step 3: Parse leaf cert + intermediates
	if len(attestationData.Certificates) == 0 {
		return status.Error(codes.InvalidArgument, "no certificate to attest")
	}
	leaf, err := x509.ParseCertificate(attestationData.Certificates[0])
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to parse leaf certificate: %v", err)
	}
	intermediates := x509.NewCertPool()
	for i, intermediateBytes := range attestationData.Certificates[1:] {
		intermediate, err := x509.ParseCertificate(intermediateBytes)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "unable to parse intermediate certificate %d: %v", i, err)
		}
		intermediates.AddCert(intermediate)
	}

	// Step 4: Verify cert chain against configured CA bundle
	if _, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         config.trustBundle,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return status.Errorf(codes.PermissionDenied, "certificate verification failed: %v", err)
	}

	// Step 5: Extract hostname from cert SAN, validate it belongs to configured tailnet
	hostname, err := extractAndValidateHostname(leaf, config.tailnet)
	if err != nil {
		return status.Errorf(codes.PermissionDenied, "hostname validation failed: %v", err)
	}

	// Step 6: Challenge-response to prove key possession
	challenge, err := x509pop.GenerateChallenge(leaf)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to generate challenge: %v", err)
	}

	challengeBytes, err := json.Marshal(challenge)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal challenge: %v", err)
	}

	if err := stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{
			Challenge: challengeBytes,
		},
	}); err != nil {
		return err
	}

	// Receive and validate challenge response
	responseReq, err := stream.Recv()
	if err != nil {
		return err
	}

	response := new(x509pop.Response)
	if err := json.Unmarshal(responseReq.GetChallengeResponse(), response); err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to unmarshal challenge response: %v", err)
	}

	if err := x509pop.VerifyChallengeResponse(leaf.PublicKey, challenge, response); err != nil {
		return status.Errorf(codes.PermissionDenied, "challenge response verification failed: %v", err)
	}

	// Step 7: Query Tailscale API for device info
	client := p.hooks.newClient(config.apiKey, config.apiURL)
	deviceInfo, err := client.getDeviceByHostname(stream.Context(), config.tailnet, hostname)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to query Tailscale API: %v", err)
	}

	// Step 8: Verify device is authorized
	if !deviceInfo.Authorized {
		return status.Errorf(codes.PermissionDenied, "device %q is not authorized in tailnet", hostname)
	}

	// Step 9: Construct SPIFFE ID from API-verified facts
	agentID, err := common.MakeAgentID(config.trustDomain, config.pathTemplate, *deviceInfo)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create agent ID: %v", err)
	}

	// Step 10: TOFU check
	if err := p.AssessTOFU(stream.Context(), agentID.String(), p.log); err != nil {
		return err
	}

	// Step 11: Build selectors from API-verified device info
	selectorValues := buildSelectorValues(deviceInfo)

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       agentID.String(),
				SelectorValues: selectorValues,
				CanReattest:    true,
			},
		},
	})
}

// Configure configures the plugin.
func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.config = newConfig

	return &configv1.ConfigureResponse{}, nil
}

// Validate validates the plugin configuration.
func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

func (p *Plugin) getConfig() (*configuration, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	if p.config == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

// extractAndValidateHostname extracts the hostname from the cert SAN (DNSNames)
// and validates that it belongs to the configured tailnet.
func extractAndValidateHostname(leaf *x509.Certificate, tailnet string) (string, error) {
	suffix := "." + tailnet
	for _, name := range leaf.DNSNames {
		if strings.HasSuffix(strings.ToLower(name), strings.ToLower(suffix)) {
			return name, nil
		}
	}
	return "", fmt.Errorf("no SAN DNS name matching tailnet %q found in certificate", tailnet)
}

// buildSelectorValues builds selector values from API-verified device info.
func buildSelectorValues(info *common.DeviceInfo) []string {
	var selectors []string

	selectors = append(selectors, "hostname:"+info.Hostname)

	for _, tag := range info.Tags {
		selectors = append(selectors, "tag:"+tag)
	}

	if info.OS != "" {
		selectors = append(selectors, "os:"+info.OS)
	}

	for _, addr := range info.Addresses {
		selectors = append(selectors, "address:"+addr)
	}

	if info.User != "" {
		selectors = append(selectors, "user:"+info.User)
	}

	selectors = append(selectors, fmt.Sprintf("authorized:%t", info.Authorized))

	return selectors
}
