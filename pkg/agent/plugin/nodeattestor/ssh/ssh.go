package ssh

import (
	"context"
	"os"
	"sync"

	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/pkg/common/plugin/ssh"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/common"

	spi "github.com/spiffe/spire/proto/common/plugin"
)

const (
	defaultHostCertPath = "/etc/ssh/ssh_host_ed25519_key-cert.pub"
	defaultHostKeyPath  = "/etc/ssh/ssh_host_ed25519_key"
)

type HIDAttestorConfig struct {
	TrustDomain  string `hcl:"trust_domain"`
	HostCertPath string `hcl:"host_cert_path"`
	HostKeyPath  string `hcl:"host_key_path"`
	KnownHosts   string `hcl:"known_hosts"`
}

type HIDAttestorPlugin struct {
	*sync.RWMutex

	trustDomain  string
	hostCertPath string
	hostKeyPath  string
	knownHosts   string
}

func (p *HIDAttestorPlugin) FetchAttestationData(stream nodeattestor.FetchAttestationData_PluginStream) error {
	p.RLock()
	defer p.RUnlock()

	keycert, err := ssh.LoadKeyCert(p.hostKeyPath, p.hostCertPath)
	if err != nil {
		return ssh.AttestationStepError("loading ssh cert and key", err)
	}

	hostname, _ := os.Hostname()
	principal := keycert.FindValidPrincipal(hostname)
	if principal == "" {
		principal = keycert.ValidPrincipal()
	}
	doc := ssh.HostIdentityDocument{
		Principal:   principal,
		Certificate: keycert.MarshalCert(),
	}

	docBytes, err := doc.Bytes()
	if err != nil {
		return ssh.AttestationStepError("marshaling identity document", err)
	}

	sigBytes, sigFormat, err := keycert.Sign(docBytes)
	if err != nil {
		return ssh.AttestationStepError("signing identity document", err)
	}

	respData, err := ssh.NewAttestationBytes(docBytes, sigBytes, sigFormat)
	if err != nil {
		return ssh.AttestationStepError("serializing response", err)
	}

	// FIXME: NA should be the one dictating type of this message
	// Change the proto to just take plain byte here
	data := &common.AttestationData{
		Type: ssh.PluginName,
		Data: respData,
	}

	return stream.Send(&nodeattestor.FetchAttestationDataResponse{
		AttestationData: data,
		SpiffeId:        ssh.SpiffeID(p.trustDomain, doc.Principal).String(),
	})
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

	p.hostCertPath = plugin.StringConfigOrDefault(config.HostCertPath, defaultHostCertPath)
	p.hostKeyPath = plugin.StringConfigOrDefault(config.HostKeyPath, defaultHostKeyPath)
	p.knownHosts = plugin.StringConfigOrDefault(config.KnownHosts, ssh.DefaultKnownHostsPath)

	return resp, nil
}

func (*HIDAttestorPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func New() nodeattestor.Plugin {
	return &HIDAttestorPlugin{
		RWMutex: &sync.RWMutex{},
	}
}
