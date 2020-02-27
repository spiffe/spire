package spireplugin

import (
	"context"
	"crypto/x509"
	"errors"
	"net/url"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/api/node"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	return catalog.MakePlugin(pluginName, upstreamauthority.PluginServer(New()))
}

type spirePlugin struct {
	mtx sync.RWMutex

	trustDomain url.URL
	config      *Configuration
}

func New() upstreamauthority.Plugin {
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

func (m *spirePlugin) MintX509CA(ctx context.Context, request *upstreamauthority.MintX509CARequest) (*upstreamauthority.MintX509CAResponse, error) {
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

	return &upstreamauthority.MintX509CAResponse{
		X509CaChain:       certsToRawCerts(certChain),
		UpstreamX509Roots: certsToRawCerts(bundle.RootCAs()),
	}, nil
}

func (m *spirePlugin) PublishJWTKey(ctx context.Context, req *upstreamauthority.PublishJWTKeyRequest) (*upstreamauthority.PublishJWTKeyResponse, error) {
	return nil, makeError(codes.Unimplemented, "publishing upstream is unsupported")
}

func (m *spirePlugin) PublishX509CA(ctx context.Context, req *upstreamauthority.PublishX509CARequest) (*upstreamauthority.PublishX509CAResponse, error) {
	return nil, makeError(codes.Unimplemented, "publishing upstream is unsupported")
}

func makeError(code codes.Code, format string, args ...interface{}) error {
	return status.Errorf(code, "upstreamauthority-spire: "+format, args...)
}

func certsToRawCerts(certs []*x509.Certificate) [][]byte {
	var rawCerts [][]byte
	for _, cert := range certs {
		rawCerts = append(rawCerts, cert.Raw)
	}
	return rawCerts
}
