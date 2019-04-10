package awssecret

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/hcl"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/upstreamca"
)

const (
	pluginName = "awssecret"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *AWSSecretPlugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName,
		upstreamca.PluginServer(p),
	)
}

type AWSSecretConfiguration struct {
	TTL             string `hcl:"ttl" json:"ttl"` // time to live for generated certs
	Region          string `hcl:"region" json:"region"`
	CertFileARN     string `hcl:"cert_file_arn" json:"cert_file_arn"`
	KeyFileARN      string `hcl:"key_file_arn" json:"key_file_arn"`
	AccessKeyID     string `hcl:"access_key_id" json:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key" json:"secret_access_key"`
	SecurityToken   string `hcl:"secret_token" json:"secret_token"`
}

type AWSSecretPlugin struct {
	serialNumber x509util.SerialNumber

	mtx        sync.RWMutex
	cert       *x509.Certificate
	upstreamCA *x509svid.UpstreamCA

	hooks struct {
		getenv    func(string) string
		newClient func(config *AWSSecretConfiguration, region string) (secretsManagerClient, error)
	}
}

func New() *AWSSecretPlugin {
	return newPlugin(newSecretsManagerClient)
}

func newPlugin(newClient func(config *AWSSecretConfiguration, region string) (secretsManagerClient, error)) *AWSSecretPlugin {
	p := &AWSSecretPlugin{
		serialNumber: x509util.NewSerialNumber(),
	}
	p.hooks.getenv = os.Getenv
	p.hooks.newClient = newClient
	return p
}

func (m *AWSSecretPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config, ttl, err := m.validateConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	// set the AWS configuration and reset clients +
	// Set local vars from config struct

	sm, err := m.hooks.newClient(config, config.Region)

	if err != nil {
		return nil, err
	}

	key, cert, err := fetchFromSecretsManager(ctx, config, sm)
	if err != nil {
		return nil, err
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	m.cert = cert
	m.upstreamCA = x509svid.NewUpstreamCA(
		x509util.NewMemoryKeypair(cert, key),
		req.GlobalConfig.TrustDomain,
		x509svid.UpstreamCAOptions{
			SerialNumber: m.serialNumber,
			TTL:          ttl,
		})

	return &spi.ConfigureResponse{}, nil
}

func (*AWSSecretPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (m *AWSSecretPlugin) SubmitCSR(ctx context.Context, request *upstreamca.SubmitCSRRequest) (*upstreamca.SubmitCSRResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.upstreamCA == nil {
		return nil, errors.New("invalid state: not configured")
	}

	cert, err := m.upstreamCA.SignCSR(ctx, request.Csr)
	if err != nil {
		return nil, err
	}

	return &upstreamca.SubmitCSRResponse{
		SignedCertificate: &upstreamca.SignedCertificate{
			CertChain: cert.Raw,
			Bundle:    m.cert.Raw,
		},
	}, nil
}

func fetchFromSecretsManager(ctx context.Context, config *AWSSecretConfiguration, sm secretsManagerClient) (crypto.PrivateKey, *x509.Certificate, error) {
	keyPEMstr, err := readARN(ctx, sm, config.KeyFileARN)

	if err != nil {
		return nil, nil, fmt.Errorf("unable to read %s: %s", config.KeyFileARN, err)
	}

	key, err := pemutil.ParsePrivateKey([]byte(keyPEMstr))
	if err != nil {
		return nil, nil, err
	}

	certPEMstr, err := readARN(ctx, sm, config.CertFileARN)

	if err != nil {
		return nil, nil, fmt.Errorf("unable to read %s: %s", config.CertFileARN, err)
	}

	cert, err := pemutil.ParseCertificate([]byte(certPEMstr))
	if err != nil {
		return nil, nil, err
	}

	// Validate cert matches private key
	matched, err := x509util.CertificateMatchesPrivateKey(cert, key)
	if err != nil {
		return nil, nil, err
	}

	if !matched {
		return nil, nil, errors.New("certificate and private key does not match")
	}

	return key, cert, nil
}

func (m *AWSSecretPlugin) validateConfig(ctx context.Context, req *spi.ConfigureRequest) (*AWSSecretConfiguration, time.Duration, error) {
	// Parse HCL config payload into config struct

	config := new(AWSSecretConfiguration)

	if err := hcl.Decode(&config, req.Configuration); err != nil {
		return nil, -1, err
	}

	if req.GlobalConfig == nil {
		return nil, -1, errors.New("global configuration is required")
	}

	if req.GlobalConfig.TrustDomain == "" {
		return nil, -1, errors.New("trust_domain is required")
	}

	// Set defaults from the environment
	if config.SecurityToken == "" {
		config.SecurityToken = m.hooks.getenv("AWS_SESSION_TOKEN")
	}

	ttl, err := time.ParseDuration(config.TTL)
	if err != nil {
		return nil, -1, fmt.Errorf("invalid TTL value: %v", err)
	}

	switch {
	case config.CertFileARN != "" && config.KeyFileARN != "":
	case config.CertFileARN != "" && config.KeyFileARN == "":
		return nil, -1, errors.New("configuration missing key ARN")
	case config.CertFileARN == "" && config.KeyFileARN != "":
		return nil, -1, errors.New("configuration missing cert ARN")
	case config.CertFileARN == "" && config.KeyFileARN == "":
		return nil, -1, errors.New("configuration missing both cert ARN and key ARN")
	}

	return config, ttl, nil
}
