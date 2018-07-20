package k8s

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/common/plugin"
)

const (
	pluginName = "k8s"
)

type configData struct {
	spiffeID        string
	privateKey      crypto.PrivateKey
	attestationData *common.AttestationData
}

type K8sConfig struct {
	TrustDomain     string `hcl:"trust_domain"`
	PrivateKeyPath  string `hcl:"k8s_private_key_path"`
	CertificatePath string `hcl:"k8s_certificate_path"`
	K8sCACertPath   string `hcl:"k8s_ca_cert_path"`
	KubeconfigPath  string `hcl:"kubeconfig_path"`
}

type K8sPlugin struct {
	m sync.Mutex
	c *K8sConfig
}

var _ nodeattestor.Plugin = (*K8sPlugin)(nil)

func New() *K8sPlugin {
	return &K8sPlugin{}
}

func (p *K8sPlugin) FetchAttestationData(stream nodeattestor.FetchAttestationData_PluginStream) (err error) {
	data, err := p.loadConfigData()
	if err != nil {
		return err
	}

	// send the attestation data back to the agent
	if err := stream.Send(&nodeattestor.FetchAttestationDataResponse{
		AttestationData: data.attestationData,
		SpiffeId:        data.spiffeID,
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
		return fmt.Errorf("k8s: unable to unmarshal challenge: %v", err)
	}

	// calculate and send the challenge response
	response, err := x509pop.CalculateResponse(data.privateKey, challenge)
	if err != nil {
		return fmt.Errorf("k8s: failed to calculate challenge response: %v", err)
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("k8s: unable to marshal challenge response: %v", err)
	}

	if err := stream.Send(&nodeattestor.FetchAttestationDataResponse{
		SpiffeId: data.spiffeID,
		Response: responseBytes,
	}); err != nil {
		return err
	}

	return nil
}

func (p *K8sPlugin) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := new(K8sConfig)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, fmt.Errorf("k8s: unable to decode configuration: %v", err)
	}

	if config.TrustDomain == "" {
		return nil, errors.New("k8s: trust_domain is required")
	}
	if config.PrivateKeyPath == "" {
		return nil, errors.New("k8s: private_key_path is required")
	}
	if config.CertificatePath == "" {
		return nil, errors.New("k8s: certificate_path is required")
	}
	if config.K8sCACertPath == "" {
		return nil, errors.New("k8s: certificate_path is required")
	}

	// make sure the configuration produces valid data
	/*
		if _, err := loadConfigData(config); err != nil {
			return nil, err
		}
	*/

	p.setConfig(config)

	return &plugin.ConfigureResponse{}, nil
}

func (p *K8sPlugin) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}

func (p *K8sPlugin) getConfig() *K8sConfig {
	p.m.Lock()
	defer p.m.Unlock()
	return p.c
}

func (p *K8sPlugin) setConfig(c *K8sConfig) {
	p.m.Lock()
	defer p.m.Unlock()
	p.c = c
}

func (p *K8sPlugin) loadConfigData() (*configData, error) {
	config := p.getConfig()
	if config == nil {
		return nil, errors.New("k8s: not configured")
	}
	return loadConfigData(config)
}

func loadConfigData(config *K8sConfig) (*configData, error) {
	k8sCert, err := fetchK8sCert(config.KubeconfigPath, config.CertificatePath, config.PrivateKeyPath, config.K8sCACertPath)
	if err != nil {
		return nil, fmt.Errorf("k8s: unable to retrieve identity document: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(k8sCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("k8s: error parsing identity document: %v", err)
	}

	attestationDataBytes, err := json.Marshal(x509pop.AttestationData{
		Certificates: k8sCert.Certificate,
	})
	if err != nil {
		return nil, fmt.Errorf("k8s: unable to marshal attestation data: %v", err)
	}

	return &configData{
		spiffeID:   k8s.SpiffeID(config.TrustDomain, parsedCert),
		privateKey: k8sCert.PrivateKey,
		attestationData: &common.AttestationData{
			Type: pluginName,
			Data: attestationDataBytes,
		},
	}, nil
}
