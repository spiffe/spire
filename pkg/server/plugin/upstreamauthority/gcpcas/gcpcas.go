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
	"google.golang.org/api/iterator"
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

// BuiltIn constructs a catalog Plugin using a new instance of this plugin.
func BuiltIn() catalog.Plugin {
	return builtin(New())
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
	RootSpec CertificateAuthoritySpec `hcl:"root_cert_spec,block"`
}

type CAClient interface {
	CreateCertificate(ctx context.Context, req *privatecapb.CreateCertificateRequest) (*privatecapb.Certificate, error)
	LoadCertificateAuthorities(ctx context.Context, spec CertificateAuthoritySpec) ([]*privatecapb.CertificateAuthority, error)
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
	return status.Error(codes.Unimplemented, "publishing upstream is unsupported")
}

func (p *Plugin) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	p.log.Warn("This plugin relies on GCP Certificate Authority Service which is currently in Beta")
	// Parse HCL config payload into config struct
	config := new(Config)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}
	// Without a project and location, we can never locate CAs
	if config.RootSpec.Project == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration has empty root_cert_spec.Project property")
	}
	if config.RootSpec.Location == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration has empty root_cert_spec.Location property")
	}
	// Even LabelKey/Value pair is necessary
	if config.RootSpec.LabelKey == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration has empty root_cert_spec.LabelKey property")
	}
	if config.RootSpec.LabelValue == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration has empty root_cert_spec.LabelValue property")
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
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}

	return p.c, nil
}

func (p *Plugin) setConfig(c *Config) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.c = c
}

func (p *Plugin) mintX509CA(ctx context.Context, csr []byte, preferredTTL int32) (*upstreamauthority.MintX509CAResponse, error) {
	p.log.Debug("Request to GCP_CAS to mint new X509")
	csrParsed, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to parse CSR: %v", err)
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
		return nil, status.Errorf(codes.Internal, "failed to load root CAs: %v", err)
	}
	if len(allCertRoots) == 0 {
		rootSpec := config.RootSpec
		return nil, status.Errorf(codes.InvalidArgument, "no certificate authorities found with label pair %q:%q", rootSpec.LabelKey, rootSpec.LabelValue)
	}

	// We dont want to use revoked, disabled or pending deletion CAs
	// In short, we only need CAs that are in enabled state
	allCertRoots = filterOutNonEnabledCAs(allCertRoots)
	// we want the CA that is expiring the earliest
	// so sort and grab the first one
	sortCAsByExpiryTime(allCertRoots)
	if len(allCertRoots) == 0 {
		rootSpec := config.RootSpec
		return nil, status.Errorf(codes.InvalidArgument, "no certificate authorities found in ENABLED state with label pair %q:%q",
			rootSpec.LabelKey, rootSpec.LabelValue)
	}

	chosenCA := allCertRoots[0]

	// All of the CAs that are eligible for signing are still trusted
	var trustBundle []*privatecapb.CertificateAuthority
	if len(allCertRoots) > 1 {
		trustBundle = append(trustBundle, allCertRoots[1:]...)
	}

	parentPath := chosenCA.Name
	p.log.Info("Minting X509 intermediate CA", "ca-certificate", parentPath, "ttl", validity)

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
	var uris []string
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
		return nil, status.Errorf(codes.Internal, "got no certificates in the chain")
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

	// The last certificate returned from the chain is the root, so we seed the trust bundle with that.
	rootBundle := []*x509.Certificate{certChain[len(certChain)-1]}
	// Then we append all the extra cert roots we loaded
	for _, c := range trustBundle {
		// The last element in the PemCaCertificates is the root of this particular chain
		// Note. We don't just use the CAs matched by labels from GCP because they could be
		// intermediate CAs. If so, some of the libraries including OpenSSL will fail to
		// validate them by default.
		// Please refer to "X509_V_FLAG_PARTIAL_CHAIN" in
		//    https://www.openssl.org/docs/man1.1.1/man3/X509_VERIFY_PARAM_set_flags.html
		pem := c.PemCaCertificates[len(c.PemCaCertificates)-1]
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

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, upstreamauthority.PluginServer(p))
}

func getClient(ctx context.Context) (CAClient, error) {
	// https://cloud.google.com/docs/authentication/production#go
	// The client creation implicitly uses Application Default Credentials (ADC) for authentication
	pcaClient, err := pcaapi.NewCertificateAuthorityClient(ctx)
	if err != nil {
		return nil, err
	}

	return &gcpCAClient{pcaClient}, nil
}

type gcpCAClient struct {
	pcaClient *pcaapi.CertificateAuthorityClient
}

func (client *gcpCAClient) CreateCertificate(ctx context.Context, req *privatecapb.CreateCertificateRequest) (*privatecapb.Certificate, error) {
	return client.pcaClient.CreateCertificate(ctx, req)
}
func (client *gcpCAClient) LoadCertificateAuthorities(ctx context.Context, spec CertificateAuthoritySpec) ([]*privatecapb.CertificateAuthority, error) {
	// https://pkg.go.dev/cloud.google.com/go/security/privateca/apiv1beta1#CertificateAuthorityClient.ListCertificateAuthorities
	var allCerts []*privatecapb.CertificateAuthority
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

	return allCerts, nil
}

func filterOutNonEnabledCAs(cas []*privatecapb.CertificateAuthority) []*privatecapb.CertificateAuthority {
	var filteredCAs []*privatecapb.CertificateAuthority
	for _, ca := range cas {
		// https://pkg.go.dev/google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1#CertificateAuthority_State
		// Only CA in enabled state can issue certificates
		if ca.State == privatecapb.CertificateAuthority_ENABLED {
			filteredCAs = append(filteredCAs, ca)
		}
	}
	return filteredCAs
}

// Sort in-place by ascending order of expiry time of CAs
func sortCAsByExpiryTime(cas []*privatecapb.CertificateAuthority) {
	getExpiryTime := func(ca *privatecapb.CertificateAuthority) time.Time {
		return ca.GetCreateTime().AsTime().Add(ca.GetLifetime().AsDuration())
	}
	sort.Slice(cas, func(i, j int) bool {
		return getExpiryTime(cas[i]).Before(getExpiryTime(cas[j]))
	})
}
