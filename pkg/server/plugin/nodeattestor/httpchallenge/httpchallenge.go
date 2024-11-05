package httpchallenge

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/httpchallenge"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	nodeattestorbase "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/base"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "http_challenge"
)

var (
	agentNamePattern = regexp.MustCompile("^[a-zA-z]+[a-zA-Z0-9-]$")
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func BuiltInTesting(client *http.Client, forceNonce string) catalog.BuiltIn {
	plugin := New()
	plugin.client = client
	plugin.forceNonce = forceNonce
	return builtin(plugin)
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type configuration struct {
	trustDomain       spiffeid.TrustDomain
	requiredPort      *int
	allowNonRootPorts bool
	dnsPatterns       []*regexp.Regexp
	tofu              bool
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *configuration {
	hclConfig := new(Config)
	if err := hcl.Decode(hclConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	var dnsPatterns []*regexp.Regexp
	for _, r := range hclConfig.AllowedDNSPatterns {
		re, err := regexp.Compile(r)
		if err != nil {
			status.ReportErrorf("cannot compile allowed_dns_pattern: %q, %s", r, err)
			continue
		}
		dnsPatterns = append(dnsPatterns, re)
	}

	allowNonRootPorts := true
	if hclConfig.AllowNonRootPorts != nil {
		allowNonRootPorts = *hclConfig.AllowNonRootPorts
	}

	tofu := true
	if hclConfig.TOFU != nil {
		tofu = *hclConfig.TOFU
	}

	mustUseTOFU := false
	switch {
	// User has explicitly asked for a required port that is untrusted
	case hclConfig.RequiredPort != nil && *hclConfig.RequiredPort >= 1024:
		mustUseTOFU = true
	// User has just chosen the defaults, any port is allowed
	case hclConfig.AllowNonRootPorts == nil && hclConfig.RequiredPort == nil:
		mustUseTOFU = true
	// User explicitly set AllowNonRootPorts to true and no required port specified
	case hclConfig.AllowNonRootPorts != nil && *hclConfig.AllowNonRootPorts && hclConfig.RequiredPort == nil:
		mustUseTOFU = true
	}

	if !tofu && mustUseTOFU {
		status.ReportError("you can not turn off trust on first use (TOFU) when non-root ports are allowed")
	}

	return &configuration{
		trustDomain:       coreConfig.TrustDomain,
		dnsPatterns:       dnsPatterns,
		requiredPort:      hclConfig.RequiredPort,
		allowNonRootPorts: allowNonRootPorts,
		tofu:              tofu,
	}
}

type Config struct {
	AllowedDNSPatterns []string `hcl:"allowed_dns_patterns"`
	RequiredPort       *int     `hcl:"required_port"`
	AllowNonRootPorts  *bool    `hcl:"allow_non_root_ports"`
	TOFU               *bool    `hcl:"tofu"`
}

type Plugin struct {
	nodeattestorbase.Base
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	m      sync.Mutex
	config *configuration

	log hclog.Logger

	client     *http.Client
	forceNonce string
}

func New() *Plugin {
	return &Plugin{
		client: http.DefaultClient,
	}
}

func (p *Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
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

	attestationData := new(httpchallenge.AttestationData)
	if err := json.Unmarshal(payload, attestationData); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to unmarshal data: %v", err)
	}

	if config.requiredPort != nil && attestationData.Port != *config.requiredPort {
		return status.Errorf(codes.InvalidArgument, "port %d is not allowed to be used by this server", attestationData.Port)
	}
	if (!config.allowNonRootPorts) && attestationData.Port >= 1024 {
		return status.Errorf(codes.InvalidArgument, "port %d is not allowed to be >= 1024", attestationData.Port)
	}

	if err = validateAgentName(attestationData.AgentName); err != nil {
		return err
	}

	if err = validateHostName(attestationData.HostName, config.dnsPatterns); err != nil {
		return err
	}

	challenge, err := httpchallenge.GenerateChallenge(p.forceNonce)
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

	// receive the response. We don't really care what it is but the plugin system requires it.
	_, err = stream.Recv()
	if err != nil {
		return err
	}

	p.log.Debug("Verifying challenge")

	timeoutctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpchallenge.VerifyChallenge(timeoutctx, p.client, attestationData, challenge); err != nil {
		return status.Errorf(codes.PermissionDenied, "challenge verification failed: %v", err)
	}

	spiffeid, err := httpchallenge.MakeAgentID(config.trustDomain, attestationData.HostName)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to make spiffe id: %v", err)
	}

	if config.tofu {
		if err := p.AssessTOFU(stream.Context(), spiffeid.String(), p.log); err != nil {
			return err
		}
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       spiffeid.String(),
				SelectorValues: buildSelectorValues(attestationData.HostName),
				CanReattest:    !config.tofu,
			},
		},
	})
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	p.m.Lock()
	defer p.m.Unlock()
	p.config = newConfig

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

// SetLogger sets this plugin's logger
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) getConfig() (*configuration, error) {
	p.m.Lock()
	defer p.m.Unlock()
	if p.config == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func buildSelectorValues(hostName string) []string {
	var selectorValues []string

	selectorValues = append(selectorValues, "hostname:"+hostName)

	return selectorValues
}

func validateAgentName(agentName string) error {
	l := agentNamePattern.FindAllStringSubmatch(agentName, -1)
	if len(l) != 1 || len(l[0]) == 0 || len(l[0]) > 32 {
		return status.Error(codes.InvalidArgument, "agent name is not valid")
	}
	return nil
}

func validateHostName(hostName string, dnsPatterns []*regexp.Regexp) error {
	if hostName == "localhost" {
		return status.Errorf(codes.PermissionDenied, "you can not use localhost as a hostname")
	}
	if len(dnsPatterns) == 0 {
		return nil
	}
	for _, re := range dnsPatterns {
		l := re.FindAllStringSubmatch(hostName, -1)
		if len(l) > 0 {
			return nil
		}
	}
	return status.Errorf(codes.PermissionDenied, "the requested hostname is not allowed to connect")
}
