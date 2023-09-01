package x509pop

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	"github.com/spiffe/spire/pkg/common/util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "x509pop"
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
	trustBundle  *x509.CertPool
	pathTemplate *agentpathtemplate.Template
}

type Config struct {
	CABundlePath      string   `hcl:"ca_bundle_path"`
	CABundlePaths     []string `hcl:"ca_bundle_paths"`
	AgentPathTemplate string   `hcl:"agent_path_template"`
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

	attestationData := new(x509pop.AttestationData)
	if err := json.Unmarshal(payload, attestationData); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to unmarshal data: %v", err)
	}

	// build up leaf certificate and list of intermediates
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

	// verify the chain of trust
	chains, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         config.trustBundle,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return status.Errorf(codes.PermissionDenied, "certificate verification failed: %v", err)
	}

	// now that the leaf certificate is trusted, issue a challenge to the node
	// to prove possession of the private key.
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

	// receive and validate the challenge response
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

	spiffeid, err := x509pop.MakeAgentID(config.trustDomain, config.pathTemplate, leaf)
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

	bundles, err := getBundles(hclConfig)
	if err != nil {
		return nil, err
	}

	pathTemplate := x509pop.DefaultAgentPathTemplate
	if len(hclConfig.AgentPathTemplate) > 0 {
		tmpl, err := agentpathtemplate.Parse(hclConfig.AgentPathTemplate)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to parse agent svid template: %q", hclConfig.AgentPathTemplate)
		}
		pathTemplate = tmpl
	}

	p.setConfiguration(&configuration{
		trustDomain:  trustDomain,
		trustBundle:  util.NewCertPool(bundles...),
		pathTemplate: pathTemplate,
	})

	return &configv1.ConfigureResponse{}, nil
}

func getBundles(config *Config) ([]*x509.Certificate, error) {
	var caPaths []string

	switch {
	case config.CABundlePath != "" && len(config.CABundlePaths) > 0:
		return nil, status.Error(codes.InvalidArgument, "only one of ca_bundle_path or ca_bundle_paths can be configured, not both")
	case config.CABundlePath != "":
		caPaths = append(caPaths, config.CABundlePath)
	case len(config.CABundlePaths) > 0:
		caPaths = append(caPaths, config.CABundlePaths...)
	default:
		return nil, status.Error(codes.InvalidArgument, "ca_bundle_path or ca_bundle_paths must be configured")
	}

	var cas []*x509.Certificate
	for _, caPath := range caPaths {
		certs, err := util.LoadCertificates(caPath)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "unable to load trust bundle %q: %v", caPath, err)
		}
		cas = append(cas, certs...)
	}

	return cas, nil
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

	// Used to avoid duplicating selectors.
	fingerprints := map[string]*x509.Certificate{}
	for _, chain := range chains {
		// Iterate over all the certs in the chain (skip leaf at the 0 index)
		for _, cert := range chain[1:] {
			fp := x509pop.Fingerprint(cert)
			// If the same fingerprint is generated, continue with the next certificate, because
			// a selector should have been already created for it.
			if _, ok := fingerprints[fp]; ok {
				continue
			}
			fingerprints[fp] = cert

			selectorValues = append(selectorValues, "ca:fingerprint:"+fp)
		}
	}

	if leaf.SerialNumber != nil {
		serialNumberHex := x509pop.SerialNumberHex(leaf.SerialNumber)
		selectorValues = append(selectorValues, "serialnumber:"+serialNumberHex)
	}

	return selectorValues
}
