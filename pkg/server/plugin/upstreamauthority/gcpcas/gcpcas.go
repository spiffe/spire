package gcpcas

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path"
	"sort"
	"sync"
	"time"

	pcaapi "cloud.google.com/go/security/privateca/apiv1beta1"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

const (
	// The name of the plugin
	pluginName    = "gcp_cas"
	publicKeyType = "PUBLIC KEY"
)

func makeError(code codes.Code, format string, args ...interface{}) error {
	return status.Errorf(code, "GCPCAS: "+format, args...)
}

// BuiltIn constructs a catalog Plugin using a new instance of this plugin.
func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, upstreamauthority.PluginServer(p))
}

type CertificateAuthoritySpec struct {
	Project    string `hcl:"project_name"`
	Location   string `hcl:"region_name"`
	LabelKey   string `hcl:"label_key"`
	LabelValue string `hcl:"label_value"`
}

func (spec *CertificateAuthoritySpec) caParentPath() string {
	return path.Join("projects", spec.Project, "locations", spec.Location)
}

type Config struct {
	RootSpec         CertificateAuthoritySpec   `hcl:"root_cert_spec,block"`
	TrustBundleSpecs []CertificateAuthoritySpec `hcl:"trust_bundle_cert_spec,block"`
}

type CAClient interface {
	CreateCertificate(ctx context.Context, req *privatecapb.CreateCertificateRequest) (*privatecapb.Certificate, error)
	LoadCertificateAuthorities(ctx context.Context, spec CertificateAuthoritySpec) ([]*privatecapb.CertificateAuthority, error)
}

type gcpCAClient struct {
	pcaClient *pcaapi.CertificateAuthorityClient
}

func (client *gcpCAClient) CreateCertificate(ctx context.Context, req *privatecapb.CreateCertificateRequest) (*privatecapb.Certificate, error) {
	return client.pcaClient.CreateCertificate(ctx, req)
}
func (client *gcpCAClient) LoadCertificateAuthorities(ctx context.Context, spec CertificateAuthoritySpec) ([]*privatecapb.CertificateAuthority, error) {
	// https://pkg.go.dev/cloud.google.com/go/security/privateca/apiv1beta1#CertificateAuthorityClient.ListCertificateAuthorities
	allCerts := make([]*privatecapb.CertificateAuthority, 0)
	certIt := client.pcaClient.ListCertificateAuthorities(ctx, &privatecapb.ListCertificateAuthoritiesRequest{
		Parent: spec.caParentPath(),
		Filter: fmt.Sprintf("labels.%s:%s", spec.LabelKey, spec.LabelValue),
		// There is "OrderBy" option but it seems to work only for the name field
		// So we will have to sort it by expiry timestamp at our end
	})

	p := iterator.NewPager(certIt, 20, "")
	for {
		var page []*privatecapb.CertificateAuthority

		nextPageToken, err := p.NextPage(&page)
		if err != nil {
			return nil, err
		}

		allCerts = append(allCerts, page...)
		if nextPageToken == "" {
			break
		}
	}

	filteredCAs := make([]*privatecapb.CertificateAuthority, 0, len(allCerts))
	for _, ca := range allCerts {
		// https://pkg.go.dev/google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1#CertificateAuthority_State
		// Only CA in enabled state can issue certificates
		if ca.State == privatecapb.CertificateAuthority_ENABLED {
			filteredCAs = append(filteredCAs, ca)
		}
	}

	// Let us return the CAs sorted by expiry time with the earliest expiry at the front
	getExpiryTime := func(ca *privatecapb.CertificateAuthority) time.Time {
		return ca.GetCreateTime().AsTime().Add(ca.GetLifetime().AsDuration())
	}
	sort.Slice(filteredCAs, func(i, j int) bool {
		return getExpiryTime(filteredCAs[i]).Before(getExpiryTime(filteredCAs[j]))
	})

	return filteredCAs, nil
}

type Plugin struct {
	// gRPC requires embedding either the "Unimplemented" or "Unsafe" stub as
	// a way of opting in or out of forward build compatibility.
	upstreamauthority.UnimplementedUpstreamAuthorityServer

	// mu is a mutex that protects the configuration. Plugins may at some point
	// need to support hot-reloading of configuration (by receiving another
	// call to Configure). So we need to prevent the configuration from
	// being used concurrently and make sure it is updated atomically.
	mu sync.Mutex
	c  *Config

	log hclog.Logger

	hook struct {
		getClient func(ctx context.Context) (CAClient, error)
	}
}

// These are compile time assertions that the plugin matches the interfaces the
// catalog requires to provide the plugin with a logger and host service
// broker as well as the UpstreamAuthority itself.
var _ catalog.NeedsLogger = (*Plugin)(nil)
var _ upstreamauthority.UpstreamAuthorityServer = (*Plugin)(nil)

func New() *Plugin {
	p := &Plugin{}
	p.hook.getClient = getClient
	return p
}

// SetLogger will be called by the catalog system to provide the plugin with
// a logger when it is loaded. The logger is wired up to the SPIRE core
// logger
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Mints an X.509 CA and responds with the signed X.509 CA certificate
// chain and upstream X.509 roots. If supported by the implementation,
// subsequent responses on the stream contain upstream X.509 root updates,
// otherwise the RPC is completed after sending the initial response.
//
// Implementation note:
// The stream should be kept open in the face of transient errors
// encountered while tracking changes to the upstream X.509 roots as SPIRE
// core will not reopen a closed stream until the next X.509 CA rotation.
func (p *Plugin) MintX509CA(request *upstreamauthority.MintX509CARequest, stream upstreamauthority.UpstreamAuthority_MintX509CAServer) error {
	ctx := stream.Context()

	minted, err := p.mintX509CA(ctx, request.Csr, request.PreferredTtl)
	if err != nil {
		return err
	}

	return stream.Send(minted)
}

// PublishJWTKey is not yet supported. It will return with GRPC Unimplemented error
func (p *Plugin) PublishJWTKey(*upstreamauthority.PublishJWTKeyRequest, upstreamauthority.UpstreamAuthority_PublishJWTKeyServer) error {
	return makeError(codes.Unimplemented, "publishing upstream is unsupported")
}

func (p *Plugin) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := new(Config)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, makeError(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	// Swap out the current configuration with the new configuration
	p.setConfig(config)

	return &plugin.ConfigureResponse{}, nil
}

func (p *Plugin) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}

func (p *Plugin) getConfig() (*Config, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.c == nil {
		return nil, makeError(codes.Internal, "not configured")
	}

	return p.c, nil
}

func (p *Plugin) setConfig(c *Config) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.c = c
}

func getClient(ctx context.Context) (CAClient, error) {
	creds, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		return nil, err
	}

	pcaClient, err := pcaapi.NewCertificateAuthorityClient(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, err
	}

	return &gcpCAClient{pcaClient}, nil
}

func (p *Plugin) mintX509CA(ctx context.Context, csr []byte, preferredTTL int32) (*upstreamauthority.MintX509CAResponse, error) {
	p.log.Debug("Request to GCP_CAS to mint new X509")
	csrParsed, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, makeError(codes.Internal, "unable to parse CSR: %v", err)
	}

	validity := time.Second * time.Duration(preferredTTL)

	pcaClient, err := p.hook.getClient(ctx)
	if err != nil {
		return nil, err
	}

	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}
	allCertRoots, err := pcaClient.LoadCertificateAuthorities(ctx, config.RootSpec)
	if err != nil {
		return nil, makeError(codes.Internal, "failed to load root CAs: %v", err)
	}
	if len(allCertRoots) == 0 {
		rootSpec := config.RootSpec
		return nil, makeError(codes.Internal, "no certificate authorities found with label pair %q:%q", rootSpec.LabelKey, rootSpec.LabelValue)
	}

	// The certs get returned in expiry order, and we want the one that is expiring the earliest
	// so just grab the first one and use that.
	chosenCA := allCertRoots[0]

	// All of the CAs that are eligible for signing are still trusted
	trustBundle := make([]*privatecapb.CertificateAuthority, 0, len(allCertRoots))
	trustBundle = append(trustBundle, allCertRoots...)

	// Also pick up if there any additional trust CAs ( as per label in plugin config )
	for _, spec := range config.TrustBundleSpecs {
		trustBundleCerts, err := pcaClient.LoadCertificateAuthorities(ctx, spec)
		if err != nil {
			return nil, makeError(codes.Internal, "failed to load trust bundle CAs: %v", err)
		}
		trustBundle = append(trustBundle, trustBundleCerts...)
	}

	parentPath := chosenCA.Name
	p.log.Info("Minting X509 intermediate CA ", "ca-certificate", parentPath, "ttl ", validity)

	subject := privatecapb.Subject{}
	extractFirst := func(strings []string, into *string) {
		if len(strings) > 0 {
			*into = strings[0]
		}
	}

	extractFirst(csrParsed.Subject.Organization, &subject.Organization)
	extractFirst(csrParsed.Subject.OrganizationalUnit, &subject.OrganizationalUnit)
	extractFirst(csrParsed.Subject.Locality, &subject.Locality)
	extractFirst(csrParsed.Subject.Province, &subject.Province)

	// https://pkg.go.dev/google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1#SubjectAltNames
	san := privatecapb.SubjectAltNames{}
	uris := make([]string, 0)
	for _, uri := range csrParsed.URIs {
		uris = append(uris, uri.String())
	}
	san.Uris = uris

	// https://pkg.go.dev/cloud.google.com/go/security/privateca/apiv1beta1#CertificateAuthorityClient.CreateCertificate
	createRequest := privatecapb.CreateCertificateRequest{
		Parent: parentPath,
		// https://pkg.go.dev/google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1#Certificate
		Certificate: &privatecapb.Certificate{
			Lifetime: durationpb.New(validity),
			// https://pkg.go.dev/google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1#CertificateConfig
			CertificateConfig: &privatecapb.Certificate_Config{
				Config: &privatecapb.CertificateConfig{
					PublicKey: &privatecapb.PublicKey{
						Type: privatecapb.PublicKey_PEM_EC_KEY,
						Key: pem.EncodeToMemory(
							&pem.Block{
								Type:  publicKeyType,
								Bytes: csrParsed.RawSubjectPublicKeyInfo,
							},
						),
					},
					SubjectConfig: &privatecapb.CertificateConfig_SubjectConfig{
						Subject:        &subject,
						CommonName:     csrParsed.Subject.CommonName,
						SubjectAltName: &san,
					},
					// https://cloud.google.com/certificate-authority-service/docs/reusable-configs#mutual_tls_w_path_length_0
					// https://cloud.google.com/sdk/gcloud/reference/beta/privateca/roots/create
					// https://pkg.go.dev/google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1#ReusableConfigWrapper
					// https://pkg.go.dev/google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1#ReusableConfigWrapper_ReusableConfig
					ReusableConfig: &privatecapb.ReusableConfigWrapper{
						ConfigValues: &privatecapb.ReusableConfigWrapper_ReusableConfig{
							ReusableConfig: fmt.Sprintf("projects/privateca-data/locations/%s/reusableConfigs/subordinate-mtls-pathlen-0", config.RootSpec.Location),
						},
					},
				},
			},
		},
	}

	cresp, err := pcaClient.CreateCertificate(ctx, &createRequest)
	if err != nil {
		return nil, err
	}
	if len(cresp.PemCertificateChain) == 0 {
		return nil, makeError(codes.Internal, "got no certificates in the chain")
	}

	cert, err := pemutil.ParseCertificate([]byte(cresp.GetPemCertificate()))
	if err != nil {
		return nil, err
	}

	certChain := make([]*x509.Certificate, len(cresp.PemCertificateChain))
	for i, c := range cresp.PemCertificateChain {
		certChain[i], err = pemutil.ParseCertificate([]byte(c))
		if err != nil {
			return nil, err
		}
	}

	// All else comprises the chain (including the issued certificate)
	// We don't include the root, since we pack that into the trust bundle.
	fullChain := []*x509.Certificate{cert}
	fullChain = append(fullChain, certChain[:len(certChain)-1]...)

	derChain := x509util.RawCertsFromCertificates(fullChain)

	// Then we append all the extra cert roots we loaded, plus anything we loaded from the
	// trust bundle spec
	rootBundle := make([]*x509.Certificate, 0, len(trustBundle))
	for _, c := range trustBundle {
		// Note. We are intentionally retrieving the immediate CAs from the GCP CAS that
		// matched the specified label key/value pair. If that CA itself is not a root CA
		// private root CA then we are not going to retrieve its root
		// ( i.e. c.PemCaCertificates[ len(c.PemCaCertificates) - 1 ] )
		// This is to avoid the possibility of the root being an external ceritificate which
		// might also be used to issue CAs to multiple firms / teams / applications
		pem := c.PemCaCertificates[0]
		parsed, err := pemutil.ParseCertificate([]byte(pem))
		if err != nil {
			return nil, err
		}
		rootBundle = append(rootBundle, parsed)
	}

	// We may well have specified multiple paths to the same root.
	rootBundle = x509util.DedupeCertificates(rootBundle)

	derBundle := x509util.RawCertsFromCertificates(rootBundle)

	p.log.Info("Successfully minted new X509")
	return &upstreamauthority.MintX509CAResponse{
		X509CaChain:       derChain,
		UpstreamX509Roots: derBundle,
	}, nil
}
