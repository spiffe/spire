package awssecret

import (
	"context"
	"crypto"
	"crypto/x509"
	"os"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "awssecret"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		upstreamauthorityv1.UpstreamAuthorityPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type Configuration struct {
	Region          string `hcl:"region" json:"region"`
	CertFileARN     string `hcl:"cert_file_arn" json:"cert_file_arn"`
	KeyFileARN      string `hcl:"key_file_arn" json:"key_file_arn"`
	AccessKeyID     string `hcl:"access_key_id" json:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key" json:"secret_access_key"`
	SecurityToken   string `hcl:"secret_token" json:"secret_token"`
	AssumeRoleARN   string `hcl:"assume_role_arn" json:"assume_role_arn"`
}

type Plugin struct {
	upstreamauthorityv1.UnsafeUpstreamAuthorityServer
	configv1.UnsafeConfigServer

	log hclog.Logger

	mtx        sync.RWMutex
	cert       *x509.Certificate
	upstreamCA *x509svid.UpstreamCA

	hooks struct {
		clock     clock.Clock
		getenv    func(string) string
		newClient func(ctx context.Context, config *Configuration, region string) (secretsManagerClient, error)
	}
}

func New() *Plugin {
	return newPlugin(newSecretsManagerClient)
}

func newPlugin(newClient func(ctx context.Context, config *Configuration, region string) (secretsManagerClient, error)) *Plugin {
	p := &Plugin{}
	p.hooks.clock = clock.New()
	p.hooks.getenv = os.Getenv
	p.hooks.newClient = newClient
	return p
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config, err := p.validateConfig(req)
	if err != nil {
		return nil, err
	}

	// set the AWS configuration and reset clients +
	// Set local vars from config struct
	sm, err := p.hooks.newClient(ctx, config, config.Region)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to create AWS client: %v", err)
	}

	key, cert, err := fetchFromSecretsManager(ctx, config, sm)
	if err != nil {
		return nil, err
	}

	trustDomain, err := spiffeid.TrustDomainFromString(req.CoreConfiguration.TrustDomain)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "trust_domain is malformed: %v", err)
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.cert = cert
	p.upstreamCA = x509svid.NewUpstreamCA(
		x509util.NewMemoryKeypair(cert, key),
		trustDomain,
		x509svid.UpstreamCAOptions{
			Clock: p.hooks.clock,
		})

	return &configv1.ConfigureResponse{}, nil
}

// MintX509CAAndSubscribe mints an X509CA by signing presented CSR with root CA fetched from AWS Secrets Manager
func (p *Plugin) MintX509CAAndSubscribe(request *upstreamauthorityv1.MintX509CARequest, stream upstreamauthorityv1.UpstreamAuthority_MintX509CAAndSubscribeServer) error {
	ctx := stream.Context()
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	if p.upstreamCA == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}

	cert, err := p.upstreamCA.SignCSR(ctx, request.Csr, time.Second*time.Duration(request.PreferredTtl))
	if err != nil {
		return status.Errorf(codes.Internal, "unable to sign CSR: %v", err)
	}

	x509CAChain, err := x509certificate.ToPluginProtos([]*x509.Certificate{cert})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to form response X.509 CA chain: %v", err)
	}

	upstreamX509Roots, err := x509certificate.ToPluginProtos([]*x509.Certificate{p.cert})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to form response upstream X.509 roots: %v", err)
	}

	return stream.Send(&upstreamauthorityv1.MintX509CAResponse{
		X509CaChain:       x509CAChain,
		UpstreamX509Roots: upstreamX509Roots,
	})
}

// PublishJWTKeyAndSubscribe is not implemented by the wrapper and returns a codes.Unimplemented status
func (p *Plugin) PublishJWTKeyAndSubscribe(*upstreamauthorityv1.PublishJWTKeyRequest, upstreamauthorityv1.UpstreamAuthority_PublishJWTKeyAndSubscribeServer) error {
	return status.Error(codes.Unimplemented, "publishing upstream is unsupported")
}

func fetchFromSecretsManager(ctx context.Context, config *Configuration, sm secretsManagerClient) (crypto.PrivateKey, *x509.Certificate, error) {
	keyPEMstr, err := readARN(ctx, sm, config.KeyFileARN)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "unable to read %s: %v", config.KeyFileARN, err)
	}

	key, err := pemutil.ParsePrivateKey([]byte(keyPEMstr))
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "unable to parse private key: %v", err)
	}

	certPEMstr, err := readARN(ctx, sm, config.CertFileARN)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "unable to read %s: %v", config.CertFileARN, err)
	}

	cert, err := pemutil.ParseCertificate([]byte(certPEMstr))
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "unable to parse certificate: %v", err)
	}

	// Validate cert matches private key
	matched, err := x509util.CertificateMatchesPrivateKey(cert, key)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "unable to validate certificate: %v", err)
	}

	if !matched {
		return nil, nil, status.Errorf(codes.InvalidArgument, "certificate and private key does not match")
	}

	return key, cert, nil
}

func (p *Plugin) validateConfig(req *configv1.ConfigureRequest) (*Configuration, error) {
	// Parse HCL config payload into config struct
	config := new(Configuration)

	if err := hcl.Decode(&config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if req.CoreConfiguration == nil {
		return nil, status.Error(codes.InvalidArgument, "core configuration is required")
	}

	if req.CoreConfiguration.TrustDomain == "" {
		return nil, status.Error(codes.InvalidArgument, "trust_domain is required")
	}

	// Set defaults from the environment
	if config.SecurityToken == "" {
		config.SecurityToken = p.hooks.getenv("AWS_SESSION_TOKEN")
	}

	switch {
	case config.CertFileARN != "" && config.KeyFileARN != "":
	case config.CertFileARN != "" && config.KeyFileARN == "":
		return nil, status.Error(codes.InvalidArgument, "configuration missing key ARN")
	case config.CertFileARN == "" && config.KeyFileARN != "":
		return nil, status.Error(codes.InvalidArgument, "configuration missing cert ARN")
	case config.CertFileARN == "" && config.KeyFileARN == "":
		return nil, status.Error(codes.InvalidArgument, "configuration missing both cert ARN and key ARN")
	}

	return config, nil
}
