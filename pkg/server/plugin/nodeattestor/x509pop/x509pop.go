package x509pop

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"
)

const (
	pluginName = "x509pop"
)

type configuration struct {
	trustDomain string
	trustBundle *x509.CertPool
}

type X509PoPConfig struct {
	CABundlePath string `hcl:"ca_bundle_path"`
}

type X509PoPPlugin struct {
	m sync.Mutex
	c *configuration
}

func New() *X509PoPPlugin {
	return &X509PoPPlugin{}
}

func (p *X509PoPPlugin) Attest(stream nodeattestor.Attest_PluginStream) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	c := p.getConfiguration()
	if c == nil {
		return newError("not configured")
	}

	if dataType := req.AttestationData.Type; dataType != pluginName {
		return newError("unexpected attestation data type %q", dataType)
	}

	attestationData := new(x509pop.AttestationData)
	if err := json.Unmarshal(req.AttestationData.Data, attestationData); err != nil {
		return newError("failed to unmarshal data: %v", err)
	}

	// build up leaf certificate and list of intermediates
	if len(attestationData.Certificates) == 0 {
		return newError("no certificate to attest")
	}
	leaf, err := x509.ParseCertificate(attestationData.Certificates[0])
	if err != nil {
		return newError("unable to parse leaf certificate: %v", err)
	}
	intermediates := x509.NewCertPool()
	for i, intermediateBytes := range attestationData.Certificates[1:] {
		intermediate, err := x509.ParseCertificate(intermediateBytes)
		if err != nil {
			return newError("unable to parse intermediate certificate %d: %v", i, err)
		}
		intermediates.AddCert(intermediate)
	}

	// verify the chain of trust
	chains, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         c.trustBundle,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return newError("certificate verification failed: %v", err)
	}

	// now that the leaf certificate is trusted, issue a challenge to the node
	// to prove possession of the private key.
	challenge, err := x509pop.GenerateChallenge(leaf)
	if err != nil {
		return fmt.Errorf("unable to generate challenge: %v", err)
	}

	challengeBytes, err := json.Marshal(challenge)
	if err != nil {
		return fmt.Errorf("unable to marshal challenge: %v", err)
	}

	if err := stream.Send(&nodeattestor.AttestResponse{
		Challenge: challengeBytes,
	}); err != nil {
		return err
	}

	// receive and validate the challenge response
	responseReq, err := stream.Recv()
	if err != nil {
		return err
	}

	response := new(x509pop.Response)
	if err := json.Unmarshal(responseReq.Response, response); err != nil {
		return newError("unable to unmarshal challenge response: %v", err)
	}

	if err := x509pop.VerifyChallengeResponse(leaf.PublicKey, challenge, response); err != nil {
		return newError("challenge response verification failed: %v", err)
	}

	resp := &nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: x509pop.SpiffeID(c.trustDomain, leaf),
		Selectors:    buildSelectors(leaf, chains),
	}

	if err := stream.Send(resp); err != nil {
		return err
	}

	return nil
}

func (p *X509PoPPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config := new(X509PoPConfig)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, newError("unable to decode configuration: %v", err)
	}

	if req.GlobalConfig == nil {
		return nil, newError("global configuration is required")
	}

	if req.GlobalConfig.TrustDomain == "" {
		return nil, newError("trust_domain is required")
	}

	if config.CABundlePath == "" {
		return nil, newError("ca_bundle_path is required")
	}

	trustBundle, err := util.LoadCertPool(config.CABundlePath)
	if err != nil {
		return nil, newError("unable to load trust bundle: %v", err)
	}

	p.setConfiguration(&configuration{
		trustDomain: req.GlobalConfig.TrustDomain,
		trustBundle: trustBundle,
	})

	return &spi.ConfigureResponse{}, nil
}

func (*X509PoPPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *X509PoPPlugin) getConfiguration() *configuration {
	p.m.Lock()
	defer p.m.Unlock()
	return p.c
}

func (p *X509PoPPlugin) setConfiguration(c *configuration) {
	p.m.Lock()
	defer p.m.Unlock()
	p.c = c
}

func newError(format string, args ...interface{}) error {
	return fmt.Errorf("x509pop: "+format, args...)
}

func buildSelectors(leaf *x509.Certificate, chains [][]*x509.Certificate) []*common.Selector {
	selectors := []*common.Selector{}

	if leaf.Subject.CommonName != "" {
		selectors = append(selectors, &common.Selector{
			Type: "x509pop", Value: "subject:cn:" + leaf.Subject.CommonName,
		})
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

			selectors = append(selectors, &common.Selector{
				Type: "x509pop", Value: "ca:fingerprint:" + fp,
			})
		}
	}

	return selectors
}
