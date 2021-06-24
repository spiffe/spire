package certmanager

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	cmapi "github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/certmanager/internal/v1"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	upstreamauthorityv0 "github.com/spiffe/spire/proto/spire/plugin/server/upstreamauthority/v0"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	pluginName = "cert-manager"
)

type Config struct {
	// Options which are used for configuring the target issuer to sign requests.
	// The CertificateRequest will be created in the configured namespace.
	IssuerName  string `hcl:"issuer_name" json:"issuer_name"`
	IssuerKind  string `hcl:"issuer_kind" json:"issuer_kind"`
	IssuerGroup string `hcl:"issuer_group" json:"issuer_group"`
	Namespace   string `hcl:"namespace" json:"namespace"`

	// File path to the kubeconfig used to build the generic Kubernetes client.
	KubeConfigFilePath string `hcl:"kube_config_file" json:"kube_config_file"`
}

// Event hooks used by unit tests to coordinate goroutines
type hooks struct {
	onCreateCR        func()
	onCleanupStaleCRs func()
}

type Plugin struct {
	log    hclog.Logger
	config *Config

	// trustDomain is the trust domain of this SPIRE server. Used to label
	// CertificateRequests to be cleaned-up
	trustDomain string

	// cmclient is a generic Kubernetes client for interacting with the
	// cert-manager APIs
	cmclient client.Client

	// gRPC requires embedding either the "Unimplemented" or "Unsafe" stub as
	// a way of opting in or out of forward build compatibility.
	upstreamauthorityv0.UnsafeUpstreamAuthorityServer

	// Used for synchronization in unit tests
	hooks hooks
}

func New() *Plugin {
	return &Plugin{
		// noop hooks to avoid nil checks
		hooks: hooks{
			onCreateCR:        func() {},
			onCleanupStaleCRs: func() {},
		},
	}
}

// SetLogger will be called by the catalog system to provide the plugin with
// a logger when it is loaded. The logger is wired up to the SPIRE core
// logger
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config, err := p.loadConfig(req)
	if err != nil {
		return nil, err
	}
	p.config = config

	cmclient, err := newCertManagerClient(p.config.KubeConfigFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to build cert-manager client: %w", err)
	}
	p.cmclient = cmclient

	// Used for adding labels to created CertificateRequests, which can be listed
	// for cleanup.
	p.trustDomain = req.GlobalConfig.TrustDomain

	return &spi.ConfigureResponse{}, nil
}

// loadConfig parses and defaults incoming configure requests
func (p *Plugin) loadConfig(req *spi.ConfigureRequest) (*Config, error) {
	config := new(Config)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration file: %s", err)
	}

	// namespace is a required field
	if len(config.Namespace) == 0 {
		return nil, status.Error(codes.InvalidArgument, "configuration has empty namespace property")
	}
	// issuer_name is a required field
	if len(config.IssuerName) == 0 {
		return nil, status.Error(codes.InvalidArgument, "configuration has empty issuer_name property")
	}
	// If no issuer_kind given, default to Issuer
	if len(config.IssuerKind) == 0 {
		p.log.Debug("Configuration has empty issuer_kind property, defaulting to 'Issuer'")
		config.IssuerKind = "Issuer"
	}
	// If no issuer_group given, default to cert-manager.io
	if len(config.IssuerGroup) == 0 {
		p.log.Debug("Configuration has empty issuer_group property, defaulting to 'cert-manager.io'")
		config.IssuerGroup = "cert-manager.io"
	}
	return config, nil
}

func (p *Plugin) MintX509CA(request *upstreamauthorityv0.MintX509CARequest, stream upstreamauthorityv0.UpstreamAuthority_MintX509CAServer) error {
	ctx := stream.Context()

	defer func() {
		p.log.Debug("Optimistically cleaning-up stale CertificateRequests")
		if err := p.cleanupStaleCertificateRequests(ctx); err != nil {
			p.log.Error("Failed to optimistically clean-up stale CertificateRequests", "error", err.Error())
		}

		p.hooks.onCleanupStaleCRs()
	}()

	// Build the CertificateRequest object and create it
	cr, err := p.buildCertificateRequest(request)
	if err != nil {
		return err
	}

	if err := p.cmclient.Create(ctx, cr); err != nil {
		return err
	}

	p.hooks.onCreateCR()

	log := p.log.With("namespace", cr.GetNamespace(), "name", cr.GetName())
	log.Info("Waiting for certificaterequest to be signed")

	// Poll the CertificateRequest until it is signed. If not signed after 300
	// polls, error.
	obj := client.ObjectKey{Name: cr.GetName(), Namespace: cr.GetNamespace()}
	for i := 0; true; i++ {
		if i == 60*5 { // ~1.25 mins
			log.Error("Failed to wait for CertificateRequest to become ready in time")
			return errors.New("request did not become ready in time")
		}

		time.Sleep(time.Second / 4)

		if err := p.cmclient.Get(ctx, obj, cr); err != nil {
			return err
		}

		// If the request has been denied, then return error here
		if isDenied, cond := certificateRequestHasCondition(cr, cmapi.CertificateRequestCondition{Type: "Denied", Status: "True"}); isDenied {
			log.With("reason", cond.Reason, "message", cond.Message).Error("Created CertificateRequest has been denied")
			return errors.New("request has been denied")
		}

		// If the request has failed, then return error here
		if isFailed, cond := certificateRequestHasCondition(cr, cmapi.CertificateRequestCondition{Type: "Ready", Status: "False", Reason: "Failed"}); isFailed {
			log.With("reason", cond.Reason, "message", cond.Message).Error("Created CertificateRequest has failed")
			return errors.New("request has failed")
		}

		// If the Certificate exists on the request then it is ready.
		if len(cr.Status.Certificate) > 0 {
			break
		}
	}

	// Parse signed certificate chain and CA certificate from CertificateRequest
	caChain, err := pemutil.ParseCertificates(cr.Status.Certificate)
	if err != nil {
		log.Error("Failed to parse signed certificate", "error", err.Error())
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// If the configured issuer did not populate the CA on the request we cannot
	// build the upstream roots. We can only error here.
	if len(cr.Status.CA) == 0 {
		log.Error("No CA certificate was populated in CertificateRequest so cannot build upstream roots")
		return errors.New("no upstream CA root returned from request")
	}

	upstreamRoot, err := pemutil.ParseCertificates(cr.Status.CA)
	if err != nil {
		log.Error("Failed to parse CA certificate returned from request", "error", err.Error())
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	return stream.Send(&upstreamauthorityv0.MintX509CAResponse{
		X509CaChain:       certsToRawCerts(caChain),
		UpstreamX509Roots: certsToRawCerts(upstreamRoot),
	})
}

func certsToRawCerts(certs []*x509.Certificate) [][]byte {
	var rawCerts [][]byte
	for _, cert := range certs {
		rawCerts = append(rawCerts, cert.Raw)
	}
	return rawCerts
}

func newCertManagerClient(configPath string) (client.Client, error) {
	config, err := getKubeConfig(configPath)
	if err != nil {
		return nil, err
	}

	// Build a generic Kubernetes client which has the cert-manager.io schemas
	// installed
	client, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}

	return client, nil
}

func getKubeConfig(configPath string) (*rest.Config, error) {
	if configPath != "" {
		return clientcmd.BuildConfigFromFlags("", configPath)
	}
	return rest.InClusterConfig()
}

// BuiltIn constructs a catalog.BuiltIn using a new instance of this plugin.
func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName, upstreamauthorityv0.UpstreamAuthorityPluginServer(p))
}

// PublishJWTKey is not implemented by the wrapper and returns a codes.Unimplemented status
func (*Plugin) PublishJWTKey(*upstreamauthorityv0.PublishJWTKeyRequest, upstreamauthorityv0.UpstreamAuthority_PublishJWTKeyServer) error {
	return makeError(codes.Unimplemented, "publishing upstream is unsupported")
}

func makeError(code codes.Code, format string, args ...interface{}) error {
	return status.Errorf(code, "cert-manager: "+format, args...)
}

func (*Plugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}
