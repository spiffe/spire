package spireplugin

import (
	"context"
	"crypto/x509"
	"errors"
	"net/url"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/api/node"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc"
)

const (
	pluginName                     = "spire"
	upstreamPollFreq time.Duration = 5 * time.Second
	internalPollFreq time.Duration = time.Second
)

type Configuration struct {
	ServerAddr        string `hcl:"server_address" json:"server_address"`
	ServerPort        string `hcl:"server_port" json:"server_port"`
	WorkloadAPISocket string `hcl:"workload_api_socket" json:"workload_api_socket"`
}

func BuiltIn() catalog.Plugin {
	return catalog.MakePlugin(pluginName, upstreamauthority.PluginServer(New()))
}

type Plugin struct {
	mtx         sync.RWMutex
	trustDomain url.URL
	config      *Configuration

	nodeMtx    sync.RWMutex
	nodeClient node.NodeClient
	conn       *grpc.ClientConn
	log        hclog.Logger

	pollMtx                sync.RWMutex
	stopPolling            context.CancelFunc
	currentPollSubscribers uint64

	bundleMtx     sync.RWMutex
	currentBundle common.Bundle
}

func New() *Plugin {
	return &Plugin{}
}

func (m *Plugin) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
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

func (m *Plugin) GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}

func (m *Plugin) SetLogger(log hclog.Logger) {
	m.pollMtx.Lock()
	defer m.pollMtx.Unlock()
	m.log = log.Named("upstream-authority-spire")
}

func (m *Plugin) MintX509CA(request *upstreamauthority.MintX509CARequest, stream upstreamauthority.UpstreamAuthority_MintX509CAServer) error {
	m.subscribeToPolling()
	defer m.unsubscribeToPolling()

	m.nodeMtx.RLock()
	certChain, _, err := submitCSRUpstreamCA(stream.Context(), m.nodeClient, request.Csr)
	m.nodeMtx.RUnlock()
	if err != nil {
		return err
	}

	ticker := time.NewTicker(internalPollFreq)
	var rootCAs []*common.Certificate
	for {
		select {
		case <-ticker.C:
			newRootCAs := m.getBundle().RootCas
			if !areRootsEqual(rootCAs, newRootCAs) {
				rootCAs = newRootCAs
				err := stream.Send(&upstreamauthority.MintX509CAResponse{
					X509CaChain:       certsToRawCerts(certChain),
					UpstreamX509Roots: commonCertsToRawCerts(rootCAs),
				})
				if err != nil {
					m.log.Error("cannot send X.509 CA chain and roots", "error", err)
				}
			}

		case <-stream.Context().Done():
			ticker.Stop()
			return nil
		}
	}
}

func (m *Plugin) PublishJWTKey(req *upstreamauthority.PublishJWTKeyRequest, stream upstreamauthority.UpstreamAuthority_PublishJWTKeyServer) error {
	m.subscribeToPolling()
	defer m.unsubscribeToPolling()

	m.nodeMtx.RLock()
	_, err := m.nodeClient.PushJWTKeyUpstream(stream.Context(), &node.PushJWTKeyUpstreamRequest{JwtKey: req.JwtKey})
	m.nodeMtx.RUnlock()
	if err != nil {
		return err
	}

	ticker := time.NewTicker(internalPollFreq)
	var keys []*common.PublicKey
	for {
		select {
		case <-ticker.C:
			newKeys := m.getBundle().JwtSigningKeys
			if !arePublicKeysEqual(keys, newKeys) {
				keys = newKeys
				err := stream.Send(&upstreamauthority.PublishJWTKeyResponse{
					UpstreamJwtKeys: keys,
				})
				if err != nil {
					m.log.Error("cannot send upstream JWT keys", "error", err)
				}
			}

		case <-stream.Context().Done():
			ticker.Stop()
			return nil
		}
	}
}

func (m *Plugin) pollBundleUpdates(ctx context.Context) {
	ticker := time.NewTicker(upstreamPollFreq)
	for {
		select {
		case <-ticker.C:
			m.nodeMtx.RLock()
			resp, err := m.nodeClient.FetchBundle(ctx, &node.FetchBundleRequest{})
			m.nodeMtx.RUnlock()
			if err != nil {
				m.log.Warn("failed to fetch bundle while polling", "error", err)
				continue
			}
			m.setBundle(*resp.Bundle)

		case <-ctx.Done():
			ticker.Stop()
			m.log.Debug("poll bundle updates context done", "reason", ctx.Err())
			return
		}
	}
}

func (m *Plugin) setBundle(b common.Bundle) {
	m.bundleMtx.Lock()
	defer m.bundleMtx.Unlock()
	m.currentBundle = b
}

func (m *Plugin) getBundle() common.Bundle {
	m.bundleMtx.RLock()
	defer m.bundleMtx.RUnlock()
	return m.currentBundle
}

func (m *Plugin) subscribeToPolling() {
	m.pollMtx.Lock()
	defer m.pollMtx.Unlock()
	if m.currentPollSubscribers == 0 {
		m.startPolling()
	}
	m.currentPollSubscribers++
}

func (m *Plugin) unsubscribeToPolling() {
	m.pollMtx.Lock()
	defer m.pollMtx.Unlock()
	m.currentPollSubscribers--
	if m.currentPollSubscribers == 0 {
		m.stopPolling()
	}
}

func (m *Plugin) startPolling() {
	var ctx context.Context
	ctx, m.stopPolling = context.WithCancel(context.Background())
	ready := make(chan struct{})
	go m.watchWorkloadSVID(ctx, m.config.WorkloadAPISocket, ready)
	m.log.Debug("Waiting for upstream workload API SVID")
	<-ready
	go m.pollBundleUpdates(ctx)
}

func certsToRawCerts(certs []*x509.Certificate) [][]byte {
	var rawCerts [][]byte
	for _, cert := range certs {
		rawCerts = append(rawCerts, cert.Raw)
	}
	return rawCerts
}

func commonCertsToRawCerts(certs []*common.Certificate) [][]byte {
	var rawCerts [][]byte
	for _, cert := range certs {
		rawCerts = append(rawCerts, cert.DerBytes)
	}
	return rawCerts
}

func areRootsEqual(a, b []*common.Certificate) bool {
	if len(a) != len(b) {
		return false
	}
	for i, root := range a {
		if !proto.Equal(root, b[i]) {
			return false
		}
	}
	return true
}

func arePublicKeysEqual(a, b []*common.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i, pk := range a {
		if !proto.Equal(pk, b[i]) {
			return false
		}
	}
	return true
}
