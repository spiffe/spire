package spireplugin

import (
	"context"
	"crypto/x509"
	"errors"
	"net/url"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/api/node"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/upstreamca"
	"google.golang.org/grpc/credentials"
)

const (
	pluginName = "spire"
)

type Configuration struct {
	ServerAddr        string `hcl:"server_address" json:"server_address"`
	ServerPort        string `hcl:"server_port" json:"server_port"`
	WorkloadAPISocket string `hcl:"workload_api_socket" json:"workload_api_socket"`
}

func BuiltIn() catalog.Plugin {
	return catalog.MakePlugin(pluginName, upstreamca.PluginServer(New()))
}

type spirePlugin struct {
	mtx   sync.RWMutex
	creds credentials.TransportCredentials

	trustDomain url.URL
	config      *Configuration
}

func New() upstreamca.Plugin {
	return &spirePlugin{}
}

func (m *spirePlugin) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := Configuration{}

	if err := hcl.Decode(&config, req.Configuration); err != nil {
		return nil, err
	}

	if req.GlobalConfig == nil {
		return nil, errors.New("global configuration is required")
	}

	if req.GlobalConfig.TrustDomain == "" {
		return nil, errors.New("trust_domain is required")
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	m.trustDomain = url.URL{
		Scheme: "spiffe",
		Host:   req.GlobalConfig.TrustDomain,
	}
	m.config = &config
	return &plugin.ConfigureResponse{}, nil
}

func (m *spirePlugin) GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}

func (m *spirePlugin) SubmitCSR(ctx context.Context, request *upstreamca.SubmitCSRRequest) (*upstreamca.SubmitCSRResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	wCert, wKey, wBundle, err := m.getWorkloadSVID(ctx, m.config)
	if err != nil {
		return nil, err
	}

	conn, err := m.newNodeClientConn(ctx, wCert, wKey, wBundle)
	if err != nil {
		return nil, err
	}
	nodeClient := node.NewNodeClient(conn)
	defer conn.Close()

	certChain, bundle, err := m.submitCSRUpstreamCA(ctx, nodeClient, request.Csr)
	if err != nil {
		return nil, err
	}

	return &upstreamca.SubmitCSRResponse{
		SignedCertificate: &upstreamca.SignedCertificate{
			CertChain: certificatesDER(certChain),
			Bundle:    certificatesDER(bundle.RootCAs()),
		},
	}, nil
}

func certificatesDER(certs []*x509.Certificate) (der []byte) {
	for _, cert := range certs {
		der = append(der, cert.Raw...)
	}
	return der
}
