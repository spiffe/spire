package k8s

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/pkg/common/plugin/x509pop"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/common/plugin"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/certificate/csr"
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
	K8sCACertPath   string `hcl:"k8s_ca_certificate_path"`
	KubeconfigPath  string `hcl:"kubeconfig_path"`
}

type K8sPlugin struct {
	m          sync.Mutex
	c          *K8sConfig
	kubeClient kubernetes.Interface
}

var _ nodeattestor.Plugin = (*K8sPlugin)(nil)

func getAgentName() string {
	name, err := os.Hostname()
	if err != nil {
		name = "unknown"
	}
	return name
}

func getKubeClient(kubeConfigFilePath, clientCertFilePath, clientKeyFilePath, caCertFilePath string) (kubernetes.Interface, error) {
	if kubeConfigFilePath == "" {
		// Try KUBECONFIG env variable
		kubeConfigFilePath = os.Getenv("KUBECONFIG")
		if kubeConfigFilePath == "" {
			// Still no luck, try default (home)
			home := os.Getenv("HOME")
			if home != "" {
				kubeConfigFilePath = path.Join(home, ".kube", "config")
			}
		}
	}

	if kubeConfigFilePath == "" {
		return nil, fmt.Errorf("Unable to locate kubeconfig")
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFilePath)
	if err != nil {
		return nil, fmt.Errorf("Error accessing kubeconfig %s: %v", kubeConfigFilePath, err)
	}

	config.TLSClientConfig.CertFile = clientCertFilePath
	config.TLSClientConfig.KeyFile = clientKeyFilePath
	config.TLSClientConfig.CAFile = caCertFilePath

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("Error creating clientset: %v", err)
	}
	return clientset, nil
}

func fetchK8sCert(kubeClient kubernetes.Interface) (*tls.Certificate, error) {
	key, err := cert.MakeEllipticPrivateKeyPEM()
	if err != nil {
		return nil, fmt.Errorf("Error creating private key: %v", err)
	}

	certsIntf := kubeClient.CertificatesV1beta1().CertificateSigningRequests()
	cert, err := csr.RequestNodeCertificate(certsIntf, key, types.NodeName(getAgentName()))
	if err != nil {
		return nil, fmt.Errorf("Error getting certificate: %v", err)
	}

	tlsCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("Error forming x509 key pair: %v", err)
	}
	return &tlsCert, nil
}
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
		return fmt.Errorf("k8s node attestor: unable to unmarshal challenge: %v", err)
	}

	// calculate and send the challenge response
	response, err := x509pop.CalculateResponse(data.privateKey, challenge)
	if err != nil {
		return fmt.Errorf("k8s node attestor: failed to calculate challenge response: %v", err)
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("k8s node attestor: unable to marshal challenge response: %v", err)
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
		return nil, fmt.Errorf("k8s node attestor: unable to decode configuration: %v", err)
	}

	if config.TrustDomain == "" {
		return nil, errors.New("k8s node attestor: trust_domain is required")
	}
	if config.PrivateKeyPath == "" {
		return nil, errors.New("k8s node attestor: private_key_path is required")
	}
	if config.CertificatePath == "" {
		return nil, errors.New("k8s node attestor: certificate_path is required")
	}
	if config.K8sCACertPath == "" {
		return nil, errors.New("k8s node attestor: ca_certificate_path is required")
	}

	p.setConfig(config)

	if p.kubeClient == nil {
		kubeClient, err := getKubeClient(config.KubeconfigPath, config.CertificatePath, config.PrivateKeyPath, config.K8sCACertPath)
		if err != nil {
			return nil, fmt.Errorf("Error creating Kubernetes client: %v", err)
		}
		p.kubeClient = kubeClient
	}

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
	p.kubeClient = nil
}

func (p *K8sPlugin) loadConfigData() (*configData, error) {
	config := p.getConfig()
	if config == nil {
		return nil, errors.New("k8s node attestor: not configured")
	}

	k8sCert, err := fetchK8sCert(p.kubeClient)
	if err != nil {
		return nil, fmt.Errorf("k8s node attestor: unable to retrieve identity document: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(k8sCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("k8s node attestor: error parsing identity document: %v", err)
	}

	attestationDataBytes, err := json.Marshal(x509pop.AttestationData{
		Certificates: k8sCert.Certificate,
	})
	if err != nil {
		return nil, fmt.Errorf("k8s node attestor: unable to marshal attestation data: %v", err)
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
