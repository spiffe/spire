package http

import (
	"context"
	"encoding/json"
	"regex"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/http"
	"github.com/spiffe/spire/pkg/common/util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "http"
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
	trustDomain  spiffeid.TrustDomain
	pathTemplate *agentpathtemplate.Template
	allowAlternatePorts bool
	dnsPatterns []regex.Regexp
}

type Config struct {
	DNSPatterns         []string `hcl:"dns_patterns"`
	AllowAlternatePorts bool `hcl:"allow_alternate_ports"`
	AgentPathTemplate   string `hcl:"agent_path_template"`
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

	attestationData := new(http.AttestationData)
	if err := json.Unmarshal(payload, attestationData); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to unmarshal data: %v", err)
	}

	if (!AllowAlternatePorts) && attestationData.Port != 80 {
		return status.Error(codes.InvalidArgument, "port is not allowed to be overridden by this server")
	}

	notfound := false
	for re in config.dnsPatterns {
		notfound = true
		l := re.FindAllStringSubmatch(attestationData.HostName, -1)
		if len(l) > 0 {
			notfound = false
			break
		}

	}
	if notfound {
		return status.Errorf(codes.PermissionDenied, "the requested hostname is not allowed to connect", err)
	}

	challenge, err := http.GenerateChallenge()
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

	response := new(http.Response)
	if err := json.Unmarshal(responseReq.GetChallengeResponse(), response); err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to unmarshal challenge response: %v", err)
	}

	if err := http.VerifyChallengeResponse(challenge, response); err != nil {
		return status.Errorf(codes.PermissionDenied, "challenge response verification failed: %v", err)
	}

	spiffeid, err := http.MakeAgentID(config.trustDomain, config.pathTemplate, leaf)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to make spiffe id: %v", err)
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       spiffeid.String(),
				SelectorValues: buildSelectorValues(leaf, chains),
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

	pathTemplate := http.DefaultAgentPathTemplate
	if len(hclConfig.AgentPathTemplate) > 0 {
		tmpl, err := agentpathtemplate.Parse(hclConfig.AgentPathTemplate)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to parse agent svid template: %q", hclConfig.AgentPathTemplate)
		}
		pathTemplate = tmpl
	}

	var dnsPatterns []regex.Regexp
	for r in hclConfig.DNSPatterns {
		re := regexp.MustCompile(r)
		dnsPatterns = append(dnsPatterns, re)
	}

	p.setConfiguration(&configuration{
		trustDomain:  trustDomain,
		pathTemplate: pathTemplate,
		dnsPatterns: dnsPatterns,
		allowAlternatePorts: hclConfig.AllowAlternatePorts,
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

func buildSelectorValues(leaf *x509.Certificate, chains [][]*x509.Certificate) []string {
	var selectorValues []string

	if leaf.Subject.CommonName != "" {
		selectorValues = append(selectorValues, "subject:cn:"+leaf.Subject.CommonName)
	}

	return selectorValues
}
