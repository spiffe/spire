package gcpcas

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"path"
	"sync"
	"time"

	pcaapi "cloud.google.com/go/security/privateca/apiv1beta1"
	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/zeebo/errs"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1beta1"
)

const (
	// The name of the plugin
	pluginName = "gcp_cas"
	// The header and footer type for a PEM-encoded CSR
	csrRequestType = "CERTIFICATE REQUEST"
)

var (
	// pluginErr is a convenience error class that prefixes errors with the
	// plugin name.
	pluginErr = errs.Class(pluginName)
)

// BuiltIn constructs a catalog Plugin using a new instance of this plugin.
func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, upstreamauthority.PluginServer(p))
}

type CertificateAuthoritySpec struct {
	Project    string `hcl:"gcp_project_name"`
	Location   string `hcl:"gcp_region_name"`
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
}

// These are compile time assertions that the plugin matches the interfaces the
// catalog requires to provide the plugin with a logger and host service
// broker as well as the UpstreamAuthority itself.
var _ catalog.NeedsLogger = (*Plugin)(nil)
var _ upstreamauthority.UpstreamAuthorityServer = (*Plugin)(nil)

func New() *Plugin {
	return &Plugin{}
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

func (p *Plugin) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := new(Config)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, pluginErr.New("unable to decode configuration: %v", err)
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
		return nil, pluginErr.New("not configured")
	}

	return p.c, nil
}

func (p *Plugin) setConfig(c *Config) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.c = c
}

func getClient(ctx context.Context) (*pcaapi.CertificateAuthorityClient, error) {
	creds, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		return nil, err
	}

	pcaClient, err := pcaapi.NewCertificateAuthorityClient(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, err
	}

	return pcaClient, nil
}

func pemToX509(pemStr string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(pemStr))
	if len(rest) > 0 {
		return nil, errors.New("Unexpected trailer in certificate of size " + fmt.Sprint(len(rest)))
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func loadCertificateAuthorities(ctx context.Context, client *pcaapi.CertificateAuthorityClient, spec CertificateAuthoritySpec) ([]*privatecapb.CertificateAuthority, error) {
	allCerts := make([]*privatecapb.CertificateAuthority, 0)
	certIt := client.ListCertificateAuthorities(ctx, &privatecapb.ListCertificateAuthoritiesRequest{
		Parent: spec.caParentPath(),
		Filter: "labels." + spec.LabelKey + ":" + spec.LabelValue,
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

func (p *Plugin) mintX509CA(ctx context.Context, csr []byte, preferredTtl int32) (*upstreamauthority.MintX509CAResponse, error) {
	csrParsed, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, fmt.Errorf("unable to parse CSR: %v", err)
	}

	validity := time.Second * time.Duration(preferredTtl)

	pcaClient, err := getClient(ctx)
	if err != nil {
		return nil, err
	}

	allCertRoots, err := loadCertificateAuthorities(ctx, pcaClient, p.c.RootSpec)
	if err != nil {
		return nil, fmt.Errorf("Failed to load root CAs: %v.", err)
	}
	if len(allCertRoots) == 0 {
		return nil, fmt.Errorf("No certificate authorities found with label pair %s:%s.", p.c.RootSpec.LabelKey, p.c.RootSpec.LabelValue)
	}

	// The certs get returned in issuance order, and we want the oldest, so just grab the first one and use that.
	chosenCA := allCertRoots[0]

	// The rest of them are still trusted
	trustBundle := make([]*privatecapb.CertificateAuthority, 0)
	if len(allCertRoots) > 1 {
		trustBundle = append(trustBundle, allCertRoots[1:]...)
	}

	for _, spec := range p.c.TrustBundleSpecs {
		trustBundleCerts, err := loadCertificateAuthorities(ctx, pcaClient, spec)
		if err != nil {
			return nil, fmt.Errorf("Failed to load trust bundle CAs: %v.", err)
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

	createRequest := privatecapb.CreateCertificateRequest{
		Parent: parentPath,
		Certificate: &privatecapb.Certificate{
			Lifetime: ptypes.DurationProto(validity),
			CertificateConfig: &privatecapb.Certificate_Config{
				Config: &privatecapb.CertificateConfig{
					PublicKey: &privatecapb.PublicKey{
						Type: privatecapb.PublicKey_PEM_EC_KEY,
						Key: pem.EncodeToMemory(
							&pem.Block{
								Type:  "PUBLIC KEY",
								Bytes: csrParsed.RawSubjectPublicKeyInfo,
							},
						),
					},
					SubjectConfig: &privatecapb.CertificateConfig_SubjectConfig{
						Subject:    &subject,
						CommonName: csrParsed.Subject.CommonName,
					},
					ReusableConfig: &privatecapb.ReusableConfigWrapper{
						ConfigValues: &privatecapb.ReusableConfigWrapper_ReusableConfig{
							ReusableConfig: fmt.Sprintf("projects/privateca-data/locations/%s/reusableConfigs/subordinate-mtls-pathlen-0", p.c.RootSpec.Location),
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
		return nil, fmt.Errorf("Got no certificates in the chain.")
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

	// The last certificate returned from the chain is the root, so we seed the trust bundle with that.
	bundle := []*x509.Certificate{certChain[len(certChain)-1]}

	// Then we append all the extra cert roots we loaded, plus anything we loaded from the
	// trust bundle spec
	for _, c := range trustBundle {
		// The last element in the PemCaCertificates is the root of this particular chain
		pem := c.PemCaCertificates[len(c.PemCaCertificates)-1]
		parsed, err := pemutil.ParseCertificate([]byte(pem))
		if err != nil {
			return nil, err
		}
		bundle = append(bundle, parsed)
	}

    // We may well have specified multiple paths to the same root.
    bundle = x509util.DedupeCertificates(bundle)

	derBundle := x509util.RawCertsFromCertificates(bundle)

	// All else comprises the chain (including the issued certificate)
	// We don't include the root, since we pack that into the trust bundle.
	fullChain := []*x509.Certificate{cert}
	fullChain = append(fullChain, certChain[:len(certChain)-1]...)

	derChain := x509util.RawCertsFromCertificates(fullChain)

	p.log.Info("Successfully minted new X509")
	return &upstreamauthority.MintX509CAResponse{
		X509CaChain:       derChain,
		UpstreamX509Roots: derBundle,
	}, nil
}
