package httpchallenge

import (
	"context"
	"encoding/json"
	"regexp"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/httpchallenge"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "http_challenge"
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

type configuration struct {
	trustDomain         spiffeid.TrustDomain
	pathTemplate        *agentpathtemplate.Template
	requiredPort        *int
	allowNonRootPorts   bool
	dnsPatterns         []*regexp.Regexp
	agentNamePattern    *regexp.Regexp
}

type Config struct {
	DNSPatterns         []string `hcl:"dns_patterns"`
	RequiredPort        *int     `hcl:"required_port"`
	AllowNonRootPorts   *bool    `hcl:"allow_non_root_ports"`
	AgentPathTemplate   string   `hcl:"agent_path_template"`
}

type Plugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	m      sync.Mutex
	config *configuration
}

func New() *Plugin {
	return &Plugin{}
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

	l := config.agentNamePattern.FindAllStringSubmatch(attestationData.AgentName, -1)
	if len(l) != 1 || len(l[0]) <= 0 || len(l[0]) > 32 {
		return status.Error(codes.InvalidArgument, "agent name is not valid")
	}

	notfound := false
	for _, re := range config.dnsPatterns {
		notfound = true
		l := re.FindAllStringSubmatch(attestationData.HostName, -1)
		if len(l) > 0 {
			notfound = false
			break
		}
	}
	if notfound {
		return status.Errorf(codes.PermissionDenied, "the requested hostname is not allowed to connect")
	}

	challenge, err := httpchallenge.GenerateChallenge()
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

	// receive and validate the challenge response
	responseReq, err := stream.Recv()
	if err != nil {
		return err
	}

	response := new(httpchallenge.Response)
	if err := json.Unmarshal(responseReq.GetChallengeResponse(), response); err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to unmarshal challenge response: %v", err)
	}

	if err := httpchallenge.VerifyChallengeResponse(attestationData, challenge, response); err != nil {
		return status.Errorf(codes.PermissionDenied, "challenge response verification failed: %v", err)
	}

	spiffeid, err := httpchallenge.MakeAgentID(config.trustDomain, config.pathTemplate, attestationData.HostName)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to make spiffe id: %v", err)
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       spiffeid.String(),
				SelectorValues: buildSelectorValues(attestationData.HostName),
				CanReattest:    true,
			},
		},
	})
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	hclConfig := new(Config)
	if err := hcl.Decode(hclConfig, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if req.CoreConfiguration == nil {
		return nil, status.Error(codes.InvalidArgument, "core configuration is required")
	}

	if req.CoreConfiguration.TrustDomain == "" {
		return nil, status.Error(codes.InvalidArgument, "trust_domain is required")
	}

	trustDomain, err := spiffeid.TrustDomainFromString(req.CoreConfiguration.TrustDomain)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "trust_domain is invalid: %v", err)
	}

	pathTemplate := httpchallenge.DefaultAgentPathTemplate
	if len(hclConfig.AgentPathTemplate) > 0 {
		pathTemplate, err = agentpathtemplate.Parse(hclConfig.AgentPathTemplate)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to parse agent svid template: %q", hclConfig.AgentPathTemplate)
		}
	}

	var dnsPatterns []*regexp.Regexp
	for _, r := range hclConfig.DNSPatterns {
		re := regexp.MustCompile(r)
		dnsPatterns = append(dnsPatterns, re)
	}

	agentNamePattern := regexp.MustCompile("^[a-zA-z]+[a-zA-Z0-9-]$")

	allowNonRootPorts := true
	if hclConfig.AllowNonRootPorts != nil {
		allowNonRootPorts = *hclConfig.AllowNonRootPorts
	}

	p.setConfiguration(&configuration{
		trustDomain:         trustDomain,
		pathTemplate:        pathTemplate,
		dnsPatterns:         dnsPatterns,
		requiredPort:        hclConfig.RequiredPort,
		allowNonRootPorts:   allowNonRootPorts,
		agentNamePattern:    agentNamePattern,
	})

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) getConfig() (*configuration, error) {
	p.m.Lock()
	defer p.m.Unlock()
	if p.config == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func (p *Plugin) setConfiguration(config *configuration) {
	p.m.Lock()
	defer p.m.Unlock()
	p.config = config
}

func buildSelectorValues(hostName string) []string {
	var selectorValues []string

	selectorValues = append(selectorValues, "httpchallenge:hostname:"+hostName)

	return selectorValues
}
