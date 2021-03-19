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

	"github.com/andres-erbsen/clock"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "awssecret"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName,
		upstreamauthority.PluginServer(p),
	)
}

type Config struct {
	Region          string `hcl:"region" json:"region"`
	CertFileARN     string `hcl:"cert_file_arn" json:"cert_file_arn"`
	KeyFileARN      string `hcl:"key_file_arn" json:"key_file_arn"`
	AccessKeyID     string `hcl:"access_key_id" json:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key" json:"secret_access_key"`
	SecurityToken   string `hcl:"secret_token" json:"secret_token"`
	AssumeRoleARN   string `hcl:"assume_role_arn" json:"assume_role_arn"`
}

type Plugin struct {
	upstreamauthority.UnsafeUpstreamAuthorityServer

	log hclog.Logger

	mtx        sync.RWMutex
	cert       *x509.Certificate
	upstreamCA *x509svid.UpstreamCA

	hooks struct {
		clock     clock.Clock
		getenv    func(string) string
		newClient func(config *Config, region string) (secretsManagerClient, error)
	}
}

func New() *Plugin {
	return newPlugin(newSecretsManagerClient)
}

func newPlugin(newClient func(config *Config, region string) (secretsManagerClient, error)) *Plugin {
	p := &Plugin{}
	p.hooks.clock = clock.New()
	p.hooks.getenv = os.Getenv
	p.hooks.newClient = newClient
	return p
}

func (m *Plugin) SetLogger(log hclog.Logger) {
	m.log = log
}

func (m *Plugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config, err := m.validateConfig(req)
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

	trustDomain, err := spiffeid.TrustDomainFromString(req.GlobalConfig.TrustDomain)
	if err != nil {
		return nil, err
	}

	m.cert = cert
	m.upstreamCA = x509svid.NewUpstreamCA(
		x509util.NewMemoryKeypair(cert, key),
		trustDomain,
		x509svid.UpstreamCAOptions{
			Clock: m.hooks.clock,
		})

	return &spi.ConfigureResponse{}, nil
}

func (*Plugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

// MintX509CA mints an X509CA by signing presented CSR with root CA fetched from AWS Secrets Manager
func (m *Plugin) MintX509CA(request *upstreamauthority.MintX509CARequest, stream upstreamauthority.UpstreamAuthority_MintX509CAServer) error {
	ctx := stream.Context()
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.upstreamCA == nil {
		return errors.New("invalid state: not configured")
	}

	cert, err := m.upstreamCA.SignCSR(ctx, request.Csr, time.Second*time.Duration(request.PreferredTtl))
	if err != nil {
		return err
	}

	return stream.Send(&upstreamauthority.MintX509CAResponse{
		X509CaChain:       [][]byte{cert.Raw},
		UpstreamX509Roots: [][]byte{m.cert.Raw},
	})
}

func fetchFromSecretsManager(ctx context.Context, config *Config, sm secretsManagerClient) (crypto.PrivateKey, *x509.Certificate, error) {
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

func (m *Plugin) validateConfig(req *spi.ConfigureRequest) (*Config, error) {
	// Parse HCL config payload into config struct
	config := new(Config)

	if err := hcl.Decode(&config, req.Configuration); err != nil {
		return nil, err
	}

	if req.GlobalConfig == nil {
		return nil, errors.New("global configuration is required")
	}

	if req.GlobalConfig.TrustDomain == "" {
		return nil, errors.New("trust_domain is required")
	}

	// Set defaults from the environment
	if config.SecurityToken == "" {
		config.SecurityToken = m.hooks.getenv("AWS_SESSION_TOKEN")
	}

	switch {
	case config.CertFileARN != "" && config.KeyFileARN != "":
	case config.CertFileARN != "" && config.KeyFileARN == "":
		return nil, errors.New("configuration missing key ARN")
	case config.CertFileARN == "" && config.KeyFileARN != "":
		return nil, errors.New("configuration missing cert ARN")
	case config.CertFileARN == "" && config.KeyFileARN == "":
		return nil, errors.New("configuration missing both cert ARN and key ARN")
	}

	return config, nil
}

// PublishJWTKey is not implemented by the wrapper and returns a codes.Unimplemented status
func (m *Plugin) PublishJWTKey(*upstreamauthority.PublishJWTKeyRequest, upstreamauthority.UpstreamAuthority_PublishJWTKeyServer) error {
	return makeError(codes.Unimplemented, "publishing upstream is unsupported")
}

func makeError(code codes.Code, format string, args ...interface{}) error {
	return status.Errorf(code, "aws-secret: "+format, args...)
}
