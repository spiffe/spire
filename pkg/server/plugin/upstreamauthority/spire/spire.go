package spireplugin

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/types"
	"google.golang.org/protobuf/proto"
)

const (
	pluginName       = "spire"
	upstreamPollFreq = 5 * time.Second
	internalPollFreq = time.Second
)

var clk clock.Clock = clock.New()

type Configuration struct {
	ServerAddr        string `hcl:"server_address" json:"server_address"`
	ServerPort        string `hcl:"server_port" json:"server_port"`
	WorkloadAPISocket string `hcl:"workload_api_socket" json:"workload_api_socket"`
}

func BuiltIn() catalog.Plugin {
	return catalog.MakePlugin(pluginName, upstreamauthority.PluginServer(New()))
}

type Plugin struct {
	upstreamauthority.UnsafeUpstreamAuthorityServer

	log hclog.Logger

	mtx         sync.RWMutex
	trustDomain spiffeid.TrustDomain
	config      *Configuration

	// Server's client. It uses an X509 source to fetch SVIDs from Workload API
	serverClient *serverClient

	pollMtx                sync.Mutex
	stopPolling            context.CancelFunc
	currentPollSubscribers uint64

	bundleMtx     sync.RWMutex
	bundleVersion uint64
	currentBundle *types.Bundle
}

func New() *Plugin {
	return &Plugin{
		currentBundle: &types.Bundle{},
	}
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

	// Create trust domain
	td, err := spiffeid.TrustDomainFromString(req.GlobalConfig.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("malformed trustdomain: %v", err)
	}
	m.trustDomain = td

	// Set config
	m.config = &config

	// Create spire-server client
	serverAddr := fmt.Sprintf("%s:%s", m.config.ServerAddr, m.config.ServerPort)
	workloadAPISocket := fmt.Sprintf("unix://%s", m.config.WorkloadAPISocket)
	m.serverClient = newServerClient(td.NewID(idutil.ServerIDPath), serverAddr, workloadAPISocket, m.log)

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

	certChain, roots, err := m.serverClient.newDownstreamX509CA(stream.Context(), request.Csr)
	if err != nil {
		return err
	}

	var bundles []*types.X509Certificate
	for _, cert := range roots {
		bundles = append(bundles, &types.X509Certificate{
			Asn1: cert.Raw,
		})
	}

	// Set X509 Authorities
	m.setBundleX509Authorities(bundles)

	rootCAs := []*types.X509Certificate{}
	rawChain := certsToRawCerts(certChain)
	ticker := clk.Ticker(internalPollFreq)
	defer ticker.Stop()
	for {
		newRootCAs := m.getBundle().X509Authorities
		// Send response with new X509 authorities
		if !areRootsEqual(rootCAs, newRootCAs) {
			rootCAs = newRootCAs
			err := stream.Send(&upstreamauthority.MintX509CAResponse{
				X509CaChain:       rawChain,
				UpstreamX509Roots: typeX509AuthoritiesToRaw(rootCAs),
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

	// Publish JWT authority
	resp, err := m.serverClient.publishJWTAuthority(stream.Context(), req.JwtKey)
	if err != nil {
		return err
	}

	// Set JWT authority
	m.setBundleJWTAuthorities(resp)

	keys := []*types.JWTKey{}
	ticker := clk.Ticker(internalPollFreq)
	defer ticker.Stop()
	for {
		newKeys := m.getBundle().JwtAuthorities
		// Send response when new JWT authority
		if !arePublicKeysEqual(keys, newKeys) {
			keys = newKeys
			err := stream.Send(&upstreamauthority.PublishJWTKeyResponse{
				UpstreamJwtKeys: typeJWTAuthoritiesToProto(keys),
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
	ticker := clk.Ticker(upstreamPollFreq)
	defer ticker.Stop()
	for {
		preFetchCallVersion := m.getBundleVersion()
		resp, err := m.serverClient.getBundle(ctx)
		if err != nil {
			m.log.Warn("Failed to fetch bundle while polling", "error", err)
		} else {
			m.setBundleIfVersionMatches(resp, preFetchCallVersion)
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			m.serverClient.release()
			m.log.Debug("Poll bundle updates context done", "reason", ctx.Err())
			return
		}
	}
}

func (m *Plugin) setBundleIfVersionMatches(b *types.Bundle, expectedVersion uint64) {
	m.bundleMtx.Lock()
	defer m.bundleMtx.Unlock()

	if m.bundleVersion == expectedVersion {
		m.currentBundle = cloneBundle(b)
	}
}

func (m *Plugin) getBundle() *types.Bundle {
	m.bundleMtx.RLock()
	defer m.bundleMtx.RUnlock()
	return m.currentBundle
}

func (m *Plugin) setBundleJWTAuthorities(keys []*types.JWTKey) {
	m.bundleMtx.Lock()
	defer m.bundleMtx.Unlock()
	m.currentBundle.JwtAuthorities = keys
	m.bundleVersion++
}

func (m *Plugin) setBundleX509Authorities(rootCAs []*types.X509Certificate) {
	m.bundleMtx.Lock()
	defer m.bundleMtx.Unlock()
	m.currentBundle.X509Authorities = rootCAs
	m.bundleVersion++
}

func (m *Plugin) getBundleVersion() uint64 {
	m.bundleMtx.RLock()
	defer m.bundleMtx.RUnlock()
	return m.bundleVersion
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
		// TODO: may we relase server here?
		m.stopPolling()
	}
}

func (m *Plugin) startPolling(streamCtx context.Context) error {
	var pollCtx context.Context
	pollCtx, m.stopPolling = context.WithCancel(context.Background())

	if err := m.serverClient.start(streamCtx); err != nil {
		return fmt.Errorf("failed to start server client: %v", err)
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

func areRootsEqual(a, b []*types.X509Certificate) bool {
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

func arePublicKeysEqual(a, b []*types.JWTKey) bool {
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

// typeX509AuthoritiesToRaw parses X509 authorities to raw certificates
func typeX509AuthoritiesToRaw(certs []*types.X509Certificate) [][]byte {
	var raws [][]byte
	for _, cert := range certs {
		raws = append(raws, cert.Asn1)
	}

	return raws
}

// typeJWTAuthoritiesToProto parse keys to common public keys
func typeJWTAuthoritiesToProto(keys []*types.JWTKey) []*common.PublicKey {
	var commonKeys []*common.PublicKey
	for _, key := range keys {
		commonKeys = append(commonKeys, &common.PublicKey{
			PkixBytes: key.PublicKey,
			Kid:       key.KeyId,
			NotAfter:  key.ExpiresAt,
		})
	}

	return commonKeys
}

func cloneBundle(b *types.Bundle) *types.Bundle {
	return proto.Clone(b).(*types.Bundle)
}
