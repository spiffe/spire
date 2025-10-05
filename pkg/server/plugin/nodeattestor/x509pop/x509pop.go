package x509pop

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	identityproviderv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/identityprovider/v1"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	"github.com/spiffe/spire/pkg/common/pluginconf"
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

type Config struct {
	Mode              string   `hcl:"mode"`
	SVIDPrefix        *string  `hcl:"spiffe_prefix"`
	CABundlePath      string   `hcl:"ca_bundle_path"`
	CABundlePaths     []string `hcl:"ca_bundle_paths"`
	AgentPathTemplate string   `hcl:"agent_path_template"`
}

type configuration struct {
	mode         string
	svidPrefix   string
	trustDomain  spiffeid.TrustDomain
	trustBundle  *x509.CertPool
	pathTemplate *agentpathtemplate.Template
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *configuration {
	hclConfig := new(Config)
	if err := hcl.Decode(hclConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	if hclConfig.Mode == "" {
		hclConfig.Mode = "external_pki"
	}
	if hclConfig.Mode != "external_pki" && hclConfig.Mode != "spiffe" {
		status.ReportError("mode can only be either spiffe or external_pki")
	}
	var trustBundles []*x509.Certificate
	if hclConfig.Mode == "external_pki" {
		var caPaths []string
		if hclConfig.CABundlePath != "" && len(hclConfig.CABundlePaths) > 0 {
			status.ReportError("only one of ca_bundle_path or ca_bundle_paths can be configured, not both")
		}
		if hclConfig.CABundlePath != "" {
			caPaths = []string{hclConfig.CABundlePath}
		} else {
			caPaths = hclConfig.CABundlePaths
		}
		if len(caPaths) == 0 {
			status.ReportError("one of ca_bundle_path or ca_bundle_paths must be configured")
		}

		for _, caPath := range caPaths {
			certs, err := util.LoadCertificates(caPath)
			if err != nil {
				status.ReportErrorf("unable to load trust bundle %q: %v", caPath, err)
			}
			trustBundles = append(trustBundles, certs...)
		}
	}

	if hclConfig.Mode == "spiffe" && (hclConfig.CABundlePath != "" || len(hclConfig.CABundlePaths) > 0) {
		status.ReportError("you can not use ca_bundle_path or ca_bundle_paths in spiffe mode")
	}

	pathTemplate := x509pop.DefaultAgentPathTemplateCN
	if hclConfig.Mode == "spiffe" {
		pathTemplate = x509pop.DefaultAgentPathTemplateSVID
	}
	if len(hclConfig.AgentPathTemplate) > 0 {
		tmpl, err := agentpathtemplate.Parse(hclConfig.AgentPathTemplate)
		if err != nil {
			status.ReportErrorf("failed to parse agent svid template: %q", hclConfig.AgentPathTemplate)
		}
		pathTemplate = tmpl
	}

	svidPrefix := "/spire-exchange/"
	if hclConfig.SVIDPrefix != nil {
		svidPrefix = *hclConfig.SVIDPrefix
		if !strings.HasSuffix(svidPrefix, "/") {
			svidPrefix += "/"
		}
	}

	newConfig := &configuration{
		trustDomain:  coreConfig.TrustDomain,
		trustBundle:  util.NewCertPool(trustBundles...),
		pathTemplate: pathTemplate,
		mode:         hclConfig.Mode,
		svidPrefix:   svidPrefix,
	}

	return newConfig
}

type Plugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	log hclog.Logger

	m                sync.Mutex
	config           *configuration
	identityProvider identityproviderv1.IdentityProviderServiceClient
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) BrokerHostServices(broker pluginsdk.ServiceBroker) error {
	if !broker.BrokerClient(&p.identityProvider) {
		return status.Errorf(codes.FailedPrecondition, "IdentityProvider host service is required")
	}
	return nil
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

	trustBundle := config.trustBundle
	if config.mode == "spiffe" {
		trustBundle, err = p.getTrustBundle(stream.Context())
		if err != nil {
			return status.Errorf(codes.Internal, "failed to get trust bundle: %v", err)
		}
	}

	// verify the chain of trust
	chains, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         trustBundle,
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

	svidPath := ""
	if config.mode == "spiffe" {
		var spiffeURIs []*url.URL
		for _, uri := range leaf.URIs {
			if uri.Scheme == "spiffe" {
				spiffeURIs = append(spiffeURIs, uri)
			}
		}
		if len(spiffeURIs) == 0 {
			return status.Errorf(codes.PermissionDenied, "valid SVID x509 cert not found")
		}
		svidPath = spiffeURIs[0].EscapedPath()
		if !strings.HasPrefix(svidPath, config.svidPrefix) {
			return status.Errorf(codes.PermissionDenied, "x509 cert doesnt match SVID prefix")
		}
		svidPath = strings.TrimPrefix(svidPath, config.svidPrefix)
	}

	sanSelectors := p.parseUriSanSelectors(leaf, config.trustDomain.Name())

	spiffeid, err := x509pop.MakeAgentID(config.trustDomain, config.pathTemplate, leaf, svidPath, sanSelectors)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to make spiffe id: %v", err)
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       spiffeid.String(),
				SelectorValues: buildSelectorValues(leaf, chains, sanSelectors),
				CanReattest:    true,
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

func (p *Plugin) getTrustBundle(ctx context.Context) (*x509.CertPool, error) {
	resp, err := p.identityProvider.FetchX509Identity(ctx, &identityproviderv1.FetchX509IdentityRequest{})
	if err != nil {
		return nil, err
	}
	var trustBundles []*x509.Certificate
	for _, rawcert := range resp.Bundle.X509Authorities {
		certificates, err := x509.ParseCertificates(rawcert.Asn1)
		if err != nil {
			return nil, err
		}
		trustBundles = append(trustBundles, certificates...)
	}
	if len(trustBundles) > 0 {
		return util.NewCertPool(trustBundles...), nil
	}
	p.log.Warn("No trust bundle retrieved from SPIRE")
	return nil, nil
}

func (p *Plugin) getConfig() (*configuration, error) {
	p.m.Lock()
	defer p.m.Unlock()
	if p.config == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func buildSelectorValues(leaf *x509.Certificate, chains [][]*x509.Certificate, sanSelectors map[string]string) []string {
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

	for sanUriKey, saniUriValue := range sanSelectors {
		selectorValues = append(selectorValues, "san:"+sanUriKey+":"+saniUriValue)
	}

	return selectorValues
}

func (p *Plugin) parseUriSanSelectors(leaf *x509.Certificate, trustDomain string) map[string]string {
	uriSelectorMap := make(map[string]string)
	sanPrefix := "x509pop://" + trustDomain + "/"
	for _, uri := range leaf.URIs {
		if strings.HasPrefix(uri.String(), sanPrefix) {
			segments := strings.SplitN(strings.Trim(uri.Path, "/"), "/", 2)
			if len(segments) < 2 {
				p.log.Warn(fmt.Sprintf("cannot extract x509pop san selectors from %s", uri.String()))
				continue
			}
			uriSelectorMap[segments[0]] = segments[1]
		}
	}
	return uriSelectorMap
}
