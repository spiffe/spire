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
	m.log = log
}

func (m *Plugin) MintX509CA(request *upstreamauthority.MintX509CARequest, stream upstreamauthority.UpstreamAuthority_MintX509CAServer) error {
	err := m.subscribeToPolling(stream.Context())
	if err != nil {
		return err
	}
	defer m.unsubscribeToPolling()

	certChain, err := m.submitCSRUpstreamCA(stream.Context(), request.Csr)
	if err != nil {
		return err
	}

	rootCAs := []*common.Certificate{}
	rawChain := certsToRawCerts(certChain)
	ticker := time.NewTicker(internalPollFreq)
	defer ticker.Stop()
	for {
		newRootCAs := m.getBundle().RootCas
		if !areRootsEqual(rootCAs, newRootCAs) {
			rootCAs = newRootCAs
			err := stream.Send(&upstreamauthority.MintX509CAResponse{
				X509CaChain:       rawChain,
				UpstreamX509Roots: commonCertsToRawCerts(rootCAs),
			})
			if err != nil {
				m.log.Error("Cannot send X.509 CA chain and roots", "error", err)
				return err
			}
			if rawChain != nil {
				rawChain = nil
			}
		}
		select {
		case <-ticker.C:
		case <-stream.Context().Done():
			return nil
		}
	}
}

func (m *Plugin) PublishJWTKey(req *upstreamauthority.PublishJWTKeyRequest, stream upstreamauthority.UpstreamAuthority_PublishJWTKeyServer) error {
	err := m.subscribeToPolling(stream.Context())
	if err != nil {
		return err
	}
	defer m.unsubscribeToPolling()

	err = m.pushAndSetInitialKeys(stream.Context(), req.JwtKey)
	if err != nil {
		return err
	}

	keys := []*common.PublicKey{}
	ticker := time.NewTicker(internalPollFreq)
	defer ticker.Stop()
	for {
		newKeys := m.getBundle().JwtSigningKeys
		if !arePublicKeysEqual(keys, newKeys) {
			keys = newKeys
			err := stream.Send(&upstreamauthority.PublishJWTKeyResponse{
				UpstreamJwtKeys: keys,
			})
			if err != nil {
				m.log.Error("Cannot send upstream JWT keys", "error", err)
				return err
			}
		}
		select {
		case <-ticker.C:
		case <-stream.Context().Done():
			return nil
		}
	}
}

func (m *Plugin) pollBundleUpdates(ctx context.Context) {
	ticker := time.NewTicker(upstreamPollFreq)
	defer ticker.Stop()
	for {
		err := m.fetchAndSetBundle(ctx)
		if err != nil {
			m.log.Warn("Failed to fetch bundle while polling", "error", err)
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			m.resetNodeClient(nil)
			m.log.Debug("Poll bundle updates context done", "reason", ctx.Err())
			return
		}
	}
}

func (m *Plugin) getBundle() common.Bundle {
	m.bundleMtx.RLock()
	defer m.bundleMtx.RUnlock()
	return m.currentBundle
}

func (m *Plugin) subscribeToPolling(streamCtx context.Context) error {
	m.pollMtx.Lock()
	defer m.pollMtx.Unlock()
	if m.currentPollSubscribers == 0 {
		if err := m.startPolling(streamCtx); err != nil {
			return err
		}
	}
	m.currentPollSubscribers++
	return nil
}

func (m *Plugin) unsubscribeToPolling() {
	m.pollMtx.Lock()
	defer m.pollMtx.Unlock()
	m.currentPollSubscribers--
	if m.currentPollSubscribers == 0 {
		m.stopPolling()
	}
}

func (m *Plugin) startPolling(streamCtx context.Context) error {
	var pollCtx context.Context
	pollCtx, m.stopPolling = context.WithCancel(context.Background())
	ready := make(chan struct{})
	go m.watchWorkloadSVID(pollCtx, m.config.WorkloadAPISocket, ready)
	m.log.Debug("Waiting for upstream workload API SVID")

	select {
	case <-ready:
	case <-streamCtx.Done():
		m.stopPolling()
		return streamCtx.Err()
	}

	go m.pollBundleUpdates(pollCtx)
	return nil
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
