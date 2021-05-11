package certmanager

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	cmutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	upstreamauthorityv0 "github.com/spiffe/spire/proto/spire/plugin/server/upstreamauthority/v0"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	pluginName = "cert-manager"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	// Install the cert-manager.io and meta.cert-manager.io schemas for the
	// generic Kubernetes client.
	utilruntime.Must(cmmeta.AddToScheme(scheme))
	utilruntime.Must(cmapi.AddToScheme(scheme))
}

type Config struct {
	// Options which are used for configuring the target issuer to sign requests.
	// The CertificateRequest will be created in the configured namespace.
	IssuerName  string `hcl:"issuer_name" json:"issuer_name"`
	IssuerKind  string `hcl:"issuer_kind" json:"issuer_kind"`
	IssuerGroup string `hcl:"issuer_group" json:"issuer_group"`
	Namespace   string `hcl:"namespace" json:"namespace"`

	// Filepath to the kubeconfig used to build the generic Kubernetes client.
	KubeConfigFilePath string `hcl:"kube_config_path" json:"kube_config_path"`
}

type Plugin struct {
	log    hclog.Logger
	config *Config

	// cmclient is a generic Kubernetes client which has the cert-manager.io and
	// meta.cert-manager.io schemas installed.
	cmclient client.Client

	// gRPC requires embedding either the "Unimplemented" or "Unsafe" stub as
	// a way of opting in or out of forward build compatibility.
	upstreamauthorityv0.UnsafeUpstreamAuthorityServer
}

func New() *Plugin {
	return new(Plugin)
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

	return &spi.ConfigureResponse{}, nil
}

// loadConfig parses and defaults incoming configure requests
func (p *Plugin) loadConfig(req *spi.ConfigureRequest) (*Config, error) {
	config := new(Config)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration file: %s", err)
	}

	if len(config.IssuerName) == 0 {
		return nil, status.Error(codes.InvalidArgument, "configuration has empty issuer_name property")
	}
	// If no issuer_kind given, default to Issuer
	if len(config.IssuerKind) == 0 {
		p.log.Warn("configuration has empty issuer_kind property, defaulting to 'Issuer'")
		config.IssuerKind = "Issuer"
	}
	// If no issuer_group given, default to cert-manager.io
	if len(config.IssuerGroup) == 0 {
		p.log.Warn("configuration has empty issuer_group property, defaulting to 'cert-manager.io'")
		config.IssuerGroup = "cert-manager.io"
	}
	if len(config.KubeConfigFilePath) == 0 {
		return nil, status.Error(codes.InvalidArgument, "configuration has empty kube_config_path property")
	}

	return config, nil
}

func (p *Plugin) MintX509CA(request *upstreamauthorityv0.MintX509CARequest, stream upstreamauthorityv0.UpstreamAuthority_MintX509CAServer) error {
	ctx := stream.Context()

	// Build PEM encoded CSR
	csrBuf := new(bytes.Buffer)
	err := pem.Encode(csrBuf, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: request.Csr,
	})
	if err != nil {
		return err
	}

	// Build CertificateRequest object to be created. Use a generated name to
	// avoid conflicts.
	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "spiffe-ca-",
			Namespace:    p.config.Namespace,
		},
		Spec: cmapi.CertificateRequestSpec{
			Duration: &metav1.Duration{
				Duration: time.Second * time.Duration(request.PreferredTtl),
			},
			Request: csrBuf.Bytes(),
			Usages: []cmapi.KeyUsage{
				cmapi.UsageDigitalSignature,
				cmapi.UsageKeyEncipherment,
				cmapi.UsageCertSign,
			},
			IsCA: true,
			IssuerRef: cmmeta.ObjectReference{
				Name:  p.config.IssuerName,
				Kind:  p.config.IssuerKind,
				Group: p.config.IssuerGroup,
			},
		},
	}
	if err := p.cmclient.Create(ctx, cr); err != nil {
		return err
	}

	// Poll the CertificateRequest until it is signed. If not signed after 300
	// polls, error.
	obj := client.ObjectKey{Name: cr.Name, Namespace: cr.Namespace}
	for i := 0; true; i++ {
		if i == 60*5 { // ~5 mins
			return fmt.Errorf("failed to wait for CertificateRequest %s/%s to become ready: %#+v", cr.Namespace, cr.Name, cr.Status)
		}

		time.Sleep(time.Second)

		if err := p.cmclient.Get(ctx, obj, cr); err != nil {
			return err
		}

		if cmutil.CertificateRequestIsDenied(cr) {
			cond := cmutil.GetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionDenied)
			return fmt.Errorf("created CertificateRequest %s/%s has been denied: %s:%s", cr.Namespace, cr.Name, cond.Reason, cond.Message)
		}

		if len(cr.Status.Certificate) > 0 {
			break
		}
	}

	// Parse signed certificate chain and CA certificate from CertificateRequest
	caChain, err := pemutil.ParseCertificates(cr.Status.Certificate)
	if err != nil {
		return fmt.Errorf("failed to parse signed certificate from %s/%s: %w", obj.Namespace, obj.Name, err)
	}

	// If the configured issuer did not populate the CA on the request we cannot
	// build the upstream roots. We can only error here.
	if len(cr.Status.CA) == 0 {
		return fmt.Errorf("no ca certificate was populated in request %s/%s so cannot build upstream roots", obj.Namespace, obj.Name)
	}

	upstreamRoot, err := pemutil.ParseCertificates(cr.Status.CA)
	if err != nil {
		return fmt.Errorf("failed to parse ca certificate from %s/%s: %w", obj.Namespace, obj.Name, err)
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
