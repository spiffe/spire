package certmanager

import (
	"context"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	cmapi "github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/certmanager/internal/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	pluginName = "cert-manager"
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
	// Options which are used for configuring the target issuer to sign requests.
	// The CertificateRequest will be created in the configured namespace.
	IssuerName  string `hcl:"issuer_name" json:"issuer_name"`
	IssuerKind  string `hcl:"issuer_kind" json:"issuer_kind"`
	IssuerGroup string `hcl:"issuer_group" json:"issuer_group"`
	Namespace   string `hcl:"namespace" json:"namespace"`

	// File path to the kubeconfig used to build the generic Kubernetes client.
	KubeConfigFilePath string `hcl:"kube_config_file" json:"kube_config_file"`
}

func (p *Plugin) buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *Configuration {
	newConfig := new(Configuration)
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportError("plugin configuration is malformed")
		return nil
	}

	// namespace is a required field
	if len(newConfig.Namespace) == 0 {
		status.ReportError("plugin configuration has empty namespace property")
	}
	// issuer_name is a required field
	if len(newConfig.IssuerName) == 0 {
		status.ReportError("plugin configuration has empty issuer_name property")
	}
	// If no issuer_kind given, default to Issuer
	if len(newConfig.IssuerKind) == 0 {
		status.ReportInfo("plugin configuration has empty issuer_kind property, defaulting to value 'Issuer'")
		newConfig.IssuerKind = "Issuer"
	}
	// If no issuer_group given, default to cert-manager.io
	if len(newConfig.IssuerGroup) == 0 {
		status.ReportInfo("plugin configuration has empty issuer_group property, defaulting to value 'cert-manager.io'")
		p.log.Debug("plugin configuration has empty issuer_group property, defaulting to 'cert-manager.io'")
		newConfig.IssuerGroup = "cert-manager.io"
	}

	return newConfig
}

// Event hooks used by unit tests to coordinate goroutines
type hooks struct {
	newClient         func(configPath string) (client.Client, error)
	onCreateCR        func()
	onCleanupStaleCRs func()
}

type Plugin struct {
	// gRPC requires embedding either the "Unimplemented" or "Unsafe" stub as
	// a way of opting in or out of forward build compatibility.
	upstreamauthorityv1.UnsafeUpstreamAuthorityServer
	configv1.UnsafeConfigServer

	log    hclog.Logger
	config *Configuration
	mtx    sync.RWMutex

	// trustDomain is the trust domain of this SPIRE server. Used to label
	// CertificateRequests to be cleaned-up
	trustDomain string

	// cmclient is a generic Kubernetes client for interacting with the
	// cert-manager APIs
	cmclient client.Client

	// Used for synchronization in unit tests
	hooks hooks
}

func New() *Plugin {
	return &Plugin{
		// noop hooks to avoid nil checks
		hooks: hooks{
			newClient:         newCertManagerClient,
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

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, p.buildConfig)
	if err != nil {
		return nil, err
	}

	cmclient, err := p.hooks.newClient(newConfig.KubeConfigFilePath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create cert-manager client: %v", err)
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.cmclient = cmclient
	p.config = newConfig
	// Used for adding labels to created CertificateRequests, which can be listed
	// for cleanup.
	p.trustDomain = req.CoreConfiguration.TrustDomain

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, p.buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, err
}

func (p *Plugin) MintX509CAAndSubscribe(request *upstreamauthorityv1.MintX509CARequest, stream upstreamauthorityv1.UpstreamAuthority_MintX509CAAndSubscribeServer) error {
	ctx := stream.Context()
	p.mtx.RLock()
	defer p.mtx.RUnlock()

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
		return status.Errorf(codes.Internal, "failed to build request: %v", err)
	}

	if err := p.cmclient.Create(ctx, cr); err != nil {
		return status.Errorf(codes.Internal, "failed to create object: %v", err)
	}

	p.hooks.onCreateCR()

	log := p.log.With("namespace", cr.GetNamespace(), "name", cr.GetName())
	log.Info("Waiting for certificaterequest to be signed")

	// Poll the CertificateRequest until it is signed. If not signed after 300
	// polls, error.
	obj := client.ObjectKey{Name: cr.GetName(), Namespace: cr.GetNamespace()}
	for i := 0; ; i++ {
		if i == 60*5 { // ~1.25 mins
			log.Error("Failed to wait for CertificateRequest to become ready in time")
			return status.Error(codes.Internal, "request did not become ready in time")
		}

		time.Sleep(time.Second / 4)

		if err := p.cmclient.Get(ctx, obj, cr); err != nil {
			return status.Errorf(codes.Internal, "kubernetes cluster client failed to get object: %v", err)
		}

		// If the request has been denied, then return error here
		if isDenied, cond := certificateRequestHasCondition(cr, cmapi.CertificateRequestCondition{Type: "Denied", Status: "True"}); isDenied {
			log.With("reason", cond.Reason, "message", cond.Message).Error("Created CertificateRequest has been denied")
			return status.Error(codes.PermissionDenied, "request has been denied")
		}

		// If the request has failed, then return error here
		if isFailed, cond := certificateRequestHasCondition(cr, cmapi.CertificateRequestCondition{Type: "Ready", Status: "False", Reason: "Failed"}); isFailed {
			log.With("reason", cond.Reason, "message", cond.Message).Error("Created CertificateRequest has failed")
			return status.Error(codes.Internal, "request has failed")
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
		return status.Errorf(codes.Internal, "failed to parse certificate: %v", err)
	}

	// If the configured issuer did not populate the CA on the request we cannot
	// build the upstream roots. We can only error here.
	if len(cr.Status.CA) == 0 {
		log.Error("No CA certificate was populated in CertificateRequest so cannot build upstream roots")
		return status.Error(codes.Internal, "no upstream CA root returned from request")
	}

	upstreamRoot, err := pemutil.ParseCertificates(cr.Status.CA)
	if err != nil {
		log.Error("Failed to parse CA certificate returned from request", "error", err.Error())
		return status.Errorf(codes.Internal, "failed to parse CA certificate: %v", err)
	}

	x509CAChain, err := x509certificate.ToPluginFromCertificates(caChain)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to form response X.509 CA chain: %v", err)
	}

	upstreamX509Roots, err := x509certificate.ToPluginFromCertificates(upstreamRoot)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to form response upstream X.509 roots: %v", err)
	}

	return stream.Send(&upstreamauthorityv1.MintX509CAResponse{
		X509CaChain:       x509CAChain,
		UpstreamX509Roots: upstreamX509Roots,
	})
}

// PublishJWTKey is not implemented by the wrapper and returns a codes.Unimplemented status
func (*Plugin) PublishJWTKeyAndSubscribe(*upstreamauthorityv1.PublishJWTKeyRequest, upstreamauthorityv1.UpstreamAuthority_PublishJWTKeyAndSubscribeServer) error {
	return status.Error(codes.Unimplemented, "publishing upstream is unsupported")
}

func (p *Plugin) SubscribeToLocalBundle(req *upstreamauthorityv1.SubscribeToLocalBundleRequest, stream upstreamauthorityv1.UpstreamAuthority_SubscribeToLocalBundleServer) error {
	return status.Error(codes.Unimplemented, "fetching upstream trust bundle is unsupported")
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
