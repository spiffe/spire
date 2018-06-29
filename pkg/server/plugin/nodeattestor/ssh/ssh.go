package ssh

import (
	"context"
	"sync"

	"github.com/spiffe/spire/proto/server/nodeattestor"

	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/pkg/common/plugin/ssh"
	spi "github.com/spiffe/spire/proto/common/plugin"
)

type HIDAttestorConfig struct {
	TrustDomain string `hcl:"trust_domain"`
	KnownHosts  string `hcl:"known_hosts"`
}

type HIDAttestorPlugin struct {
	*sync.RWMutex

	trustDomain string
	knownHosts  string
}

func (p *HIDAttestorPlugin) Attest(stream nodeattestor.Attest_PluginStream) error {
	p.RLock()
	defer p.RUnlock()

	req, err := stream.Recv()
	if err != nil {
		return err
	}

	data, doc, err := ssh.AttestationFromBytes(req.AttestationData.Data)
	if err != nil {
		return ssh.AttestationStepError("deserializing request", err)
	}

	cert, err := ssh.ParseCert([]byte(doc.Certificate))
	if err != nil {
		return ssh.AttestationStepError("parsing cert", err)
	}

	if err := cert.Validate(doc.Principal, p.knownHosts); err != nil {
		return ssh.AttestationStepError("validating cert against known hosts", err)
	}

	if err := cert.Verify(data.Document, data.Signature, data.SignatureFormat); err != nil {
		return ssh.AttestationStepError("verifying the signature", err)
	}

	resp := &nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: ssh.SpiffeID(p.trustDomain, doc.Principal).String(),
	}

	return stream.Send(resp)
}

func (p *HIDAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	p.Lock()
	defer p.Unlock()

	resp := &spi.ConfigureResponse{}

	config := &HIDAttestorConfig{}
	if err := plugin.ParseConfig(req.Configuration, &config); err != nil {
		resp.ErrorList = []string{err.Error()}
		return resp, ssh.AttestationStepError("parsing config", err)
	}

	p.trustDomain = config.TrustDomain

	p.knownHosts = plugin.StringConfigOrDefault(config.KnownHosts, ssh.DefaultKnownHostsPath)

	return &spi.ConfigureResponse{}, nil
}

func (*HIDAttestorPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func New() nodeattestor.Plugin {
	return &HIDAttestorPlugin{
		RWMutex: &sync.RWMutex{},
	}
}
