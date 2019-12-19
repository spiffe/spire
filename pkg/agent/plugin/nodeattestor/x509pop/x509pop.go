package x509pop

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/agent/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/common/plugin"
)

const (
	pluginName = "x509pop"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, nodeattestor.PluginServer(p))
}

type configData struct {
	privateKey      crypto.PrivateKey
	attestationData *common.AttestationData
}

type Config struct {
	trustDomain       string
	PrivateKeyPath    string `hcl:"private_key_path"`
	CertificatePath   string `hcl:"certificate_path"`
	IntermediatesPath string `hcl:"intermediates_path"`
}

type Plugin struct {
	m sync.Mutex
	c *Config
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) FetchAttestationData(stream nodeattestor.NodeAttestor_FetchAttestationDataServer) (err error) {
	data, err := p.loadConfigData()
	if err != nil {
		return err
	}

	// send the attestation data back to the agent
	if err := stream.Send(&nodeattestor.FetchAttestationDataResponse{
		AttestationData: data.attestationData,
	}); err != nil {
		return err
	}

	// receive challenge
	resp, err := stream.Recv()
	if err != nil {
		return err
	}

	challenge := new(x509pop.Challenge)
	if err := json.Unmarshal(resp.Challenge, challenge); err != nil {
		return fmt.Errorf("x509pop: unable to unmarshal challenge: %v", err)
	}

	// calculate and send the challenge response
	response, err := x509pop.CalculateResponse(data.privateKey, challenge)
	if err != nil {
		return fmt.Errorf("x509pop: failed to calculate challenge response: %v", err)
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("x509pop: unable to marshal challenge response: %v", err)
	}

	if err := stream.Send(&nodeattestor.FetchAttestationDataResponse{
		Response: responseBytes,
	}); err != nil {
		return err
	}

	return nil
}

func (p *Plugin) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := new(Config)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, fmt.Errorf("x509pop: unable to decode configuration: %v", err)
	}

	if req.GlobalConfig == nil {
		return nil, errors.New("x509pop: global configuration is required")
	}
	if req.GlobalConfig.TrustDomain == "" {
		return nil, errors.New("x509pop: trust_domain is required")
	}
	config.trustDomain = req.GlobalConfig.TrustDomain

	if config.PrivateKeyPath == "" {
		return nil, errors.New("x509pop: private_key_path is required")
	}
	if config.CertificatePath == "" {
		return nil, errors.New("x509pop: certificate_path is required")
	}

	// make sure the configuration produces valid data
	if _, err := loadConfigData(config); err != nil {
		return nil, err
	}

	p.setConfig(config)

	return &plugin.ConfigureResponse{}, nil
}

func (p *Plugin) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}

func (p *Plugin) getConfig() *Config {
	p.m.Lock()
	defer p.m.Unlock()
	return p.c
}

func (p *Plugin) setConfig(c *Config) {
	p.m.Lock()
	defer p.m.Unlock()
	p.c = c
}

func (p *Plugin) loadConfigData() (*configData, error) {
	config := p.getConfig()
	if config == nil {
		return nil, errors.New("x509pop: not configured")
	}
	return loadConfigData(config)
}

func loadConfigData(config *Config) (*configData, error) {
	certificate, err := tls.LoadX509KeyPair(config.CertificatePath, config.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("x509pop: unable to load keypair: %v", err)
	}

	certificates := certificate.Certificate

	// Append intermediate certificates if IntermediatesPath is set.
	if strings.TrimSpace(config.IntermediatesPath) != "" {
		intermediates, err := util.LoadCertificates(config.IntermediatesPath)
		if err != nil {
			return nil, fmt.Errorf("x509pop: unable to load intermediate certificates: %v", err)
		}

		for _, cert := range intermediates {
			certificates = append(certificates, cert.Raw)
		}
	}

	attestationDataBytes, err := json.Marshal(x509pop.AttestationData{
		Certificates: certificates,
	})
	if err != nil {
		return nil, fmt.Errorf("x509pop: unable to marshal attestation data: %v", err)
	}

	return &configData{
		privateKey: certificate.PrivateKey,
		attestationData: &common.AttestationData{
			Type: pluginName,
			Data: attestationDataBytes,
		},
	}, nil
}
