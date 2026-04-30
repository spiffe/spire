package vault

import (
	"context"
	"crypto/x509"
	"os"
	"strconv"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"github.com/spiffe/spire/pkg/server/common/vault"
)

const (
	pluginName = "vault"

	PluginConfigMalformed = "plugin configuration is malformed"
)

// BuiltIn constructs a catalog.BuiltIn using a new instance of this plugin.
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
	vault.BaseConfiguration `hcl:",squash"`

	// Name of the mount point where PKI secret engine is mounted. (e.g., /<mount_point>/ca/pem)
	PKIMountPoint string `hcl:"pki_mount_point" json:"pki_mount_point"`
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *Configuration {
	newConfig := new(Configuration)
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportError("plugin configuration is malformed")
		return nil
	}

	// TODO: add field validations

	// TODO: consider moving some elements of parseAuthMethod into config checking
	// TODO: consider moving some elements of genClientParams into config checking
	// TODO: consider moving some elements of NewClientConfig into config checking

	return newConfig
}

type Plugin struct {
	upstreamauthorityv1.UnsafeUpstreamAuthorityServer
	configv1.UnsafeConfigServer

	mtx    *sync.RWMutex
	logger hclog.Logger

	authMethod vault.AuthMethod
	cc         *vault.ClientConfig
	vc         *vault.Client

	hooks struct {
		lookupEnv func(string) (string, bool)
	}
}

func New() *Plugin {
	p := &Plugin{
		mtx: &sync.RWMutex{},
	}

	p.hooks.lookupEnv = os.LookupEnv

	return p
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.logger = log
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	am, err := vault.ParseAuthMethod(&newConfig.BaseConfiguration)
	if err != nil {
		return nil, err
	}
	cp, err := vault.GenClientParams(am, &newConfig.BaseConfiguration, p.hooks.lookupEnv)
	if err != nil {
		return nil, err
	}

	// Set PKI mount point
	cp.PKIMountPoint = newConfig.PKIMountPoint

	vcConfig, err := vault.NewClientConfig(cp, p.logger)
	if err != nil {
		return nil, err
	}

	p.authMethod = am
	p.cc = vcConfig

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

func (p *Plugin) MintX509CAAndSubscribe(req *upstreamauthorityv1.MintX509CARequest, stream upstreamauthorityv1.UpstreamAuthority_MintX509CAAndSubscribeServer) error {
	if p.cc == nil {
		return status.Error(codes.FailedPrecondition, "plugin not configured")
	}

	var ttl string
	if req.PreferredTtl == 0 {
		ttl = ""
	} else {
		ttl = strconv.Itoa(int(req.PreferredTtl))
	}

	csr, err := x509.ParseCertificateRequest(req.Csr)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to parse CSR data: %v", err)
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	// TODO: this is flaky, we should have a better way to manage the Vault client lifecycle
	renewCh := make(chan struct{})
	if p.vc == nil {
		vc, err := p.cc.NewAuthenticatedClient(p.authMethod, renewCh)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to prepare authenticated client: %v", err)
		}
		p.vc = vc

		// if renewCh has been closed, the token can not be renewed and may expire,
		// it needs to re-authenticate to the Vault.
		go func() {
			<-renewCh
			p.mtx.Lock()
			defer p.mtx.Unlock()
			p.vc = nil
			p.logger.Debug("Going to re-authenticate to the Vault at the next signing request time")
		}()
	}

	signResp, err := p.vc.SignIntermediate(ttl, csr)
	if err != nil {
		return err
	}
	if signResp == nil {
		return status.Error(codes.Internal, "unexpected empty response from UpstreamAuthority")
	}

	// Parse CACert in PEM format
	var upstreamRootPEM string
	if len(signResp.UpstreamCACertChainPEM) == 0 {
		upstreamRootPEM = signResp.UpstreamCACertPEM
	} else {
		upstreamRootPEM = signResp.UpstreamCACertChainPEM[len(signResp.UpstreamCACertChainPEM)-1]
	}
	upstreamRoot, err := pemutil.ParseCertificate([]byte(upstreamRootPEM))
	if err != nil {
		return status.Errorf(codes.Internal, "failed to parse Root CA certificate: %v", err)
	}

	upstreamX509Roots, err := x509certificate.ToPluginFromCertificates([]*x509.Certificate{upstreamRoot})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to form response upstream X.509 roots: %v", err)
	}

	// Parse PEM format data to get DER format data
	certificate, err := pemutil.ParseCertificate([]byte(signResp.CACertPEM))
	if err != nil {
		return status.Errorf(codes.Internal, "failed to parse certificate: %v", err)
	}
	certChain := []*x509.Certificate{certificate}
	for _, c := range signResp.UpstreamCACertChainPEM {
		if c == upstreamRootPEM {
			continue
		}
		// Since Vault v1.11.0, the signed CA certificate appears within the ca_chain
		// https://github.com/hashicorp/vault/blob/v1.11.0/changelog/15524.txt
		if c == signResp.CACertPEM {
			continue
		}

		b, err := pemutil.ParseCertificate([]byte(c))
		if err != nil {
			return status.Errorf(codes.Internal, "failed to parse upstream bundle certificates: %v", err)
		}
		certChain = append(certChain, b)
	}

	x509CAChain, err := x509certificate.ToPluginFromCertificates(certChain)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to form response X.509 CA chain: %v", err)
	}

	return stream.Send(&upstreamauthorityv1.MintX509CAResponse{
		X509CaChain:       x509CAChain,
		UpstreamX509Roots: upstreamX509Roots,
	})
}

// PublishJWTKeyAndSubscribe is not implemented by the wrapper and returns a codes.Unimplemented status
func (*Plugin) PublishJWTKeyAndSubscribe(*upstreamauthorityv1.PublishJWTKeyRequest, upstreamauthorityv1.UpstreamAuthority_PublishJWTKeyAndSubscribeServer) error {
	return status.Error(codes.Unimplemented, "publishing upstream is unsupported")
}

func (p *Plugin) SubscribeToLocalBundle(req *upstreamauthorityv1.SubscribeToLocalBundleRequest, stream upstreamauthorityv1.UpstreamAuthority_SubscribeToLocalBundleServer) error {
	return status.Error(codes.Unimplemented, "fetching upstream trust bundle is unsupported")
}
