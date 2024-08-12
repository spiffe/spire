package spireplugin

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/coretypes/bundle"
	"github.com/spiffe/spire/pkg/common/coretypes/jwtkey"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/pkg/common/idutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	pluginName       = "spire"
	upstreamPollFreq = 5 * time.Second
	internalPollFreq = time.Second
)

var clk clock.Clock = clock.New()

type Configuration struct {
	ServerAddr        string             `hcl:"server_address" json:"server_address"`
	ServerPort        string             `hcl:"server_port" json:"server_port"`
	WorkloadAPISocket string             `hcl:"workload_api_socket" json:"workload_api_socket"`
	Experimental      experimentalConfig `hcl:"experimental"`
}

type experimentalConfig struct {
	WorkloadAPINamedPipeName string `hcl:"workload_api_named_pipe_name" json:"workload_api_named_pipe_name"`
}

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		upstreamauthorityv1.UpstreamAuthorityPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type Plugin struct {
	upstreamauthorityv1.UnsafeUpstreamAuthorityServer
	configv1.UnsafeConfigServer

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
	currentBundle *plugintypes.Bundle
}

func New() *Plugin {
	return &Plugin{
		currentBundle: &plugintypes.Bundle{},
	}
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := new(Configuration)

	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if req.CoreConfiguration == nil {
		return nil, status.Error(codes.InvalidArgument, "core configuration is required")
	}

	if req.CoreConfiguration.TrustDomain == "" {
		return nil, status.Error(codes.InvalidArgument, "trust_domain is required")
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	// Create trust domain
	td, err := spiffeid.TrustDomainFromString(req.CoreConfiguration.TrustDomain)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "trust_domain is malformed: %v", err)
	}
	p.trustDomain = td

	// Set config
	p.config = config

	// Create spire-server client
	serverAddr := fmt.Sprintf("%s:%s", p.config.ServerAddr, p.config.ServerPort)
	workloadAPIAddr, err := p.getWorkloadAPIAddr()
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to set Workload API address: %v", err)
	}

	serverID, err := idutil.ServerID(td)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to build server ID: %v", err)
	}

	p.serverClient = newServerClient(serverID, serverAddr, workloadAPIAddr, p.log)

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) MintX509CAAndSubscribe(request *upstreamauthorityv1.MintX509CARequest, stream upstreamauthorityv1.UpstreamAuthority_MintX509CAAndSubscribeServer) error {
	err := p.subscribeToPolling(stream.Context())
	if err != nil {
		return err
	}
	defer p.unsubscribeToPolling()

	certChain, roots, err := p.serverClient.newDownstreamX509CA(stream.Context(), request.Csr, request.PreferredTtl)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to request a new Downstream X509CA: %v", err)
	}

	var bundles []*plugintypes.X509Certificate
	for _, cert := range roots {
		pluginCert, err := x509certificate.ToPluginProto(cert)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to parse X.509 authorities: %v", err)
		}

		bundles = append(bundles, pluginCert)
	}

	// Set X509 Authorities
	p.setBundleX509Authorities(bundles)

	rootCAs := []*plugintypes.X509Certificate{}

	x509CAChain, err := x509certificate.ToPluginProtos(certChain)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to form response X.509 CA chain: %v", err)
	}

	ticker := clk.Ticker(internalPollFreq)
	defer ticker.Stop()
	for {
		newRootCAs := p.getBundle().X509Authorities
		// Send response with new X509 authorities
		if !areRootsEqual(rootCAs, newRootCAs) {
			rootCAs = newRootCAs
			err := stream.Send(&upstreamauthorityv1.MintX509CAResponse{
				X509CaChain:       x509CAChain,
				UpstreamX509Roots: rootCAs,
			})
			if err != nil {
				p.log.Error("Cannot send X.509 CA chain and roots", "error", err)
				return err
			}
			if len(x509CAChain) > 0 {
				x509CAChain = nil
			}
		}
		select {
		case <-ticker.C:
		case <-stream.Context().Done():
			return nil
		}
	}
}

func (p *Plugin) PublishJWTKeyAndSubscribe(req *upstreamauthorityv1.PublishJWTKeyRequest, stream upstreamauthorityv1.UpstreamAuthority_PublishJWTKeyAndSubscribeServer) error {
	err := p.subscribeToPolling(stream.Context())
	if err != nil {
		return err
	}
	defer p.unsubscribeToPolling()

	jwtKey, err := jwtkey.ToAPIFromPluginProto(req.JwtKey)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to parse JWTKey into api JWTKey: %v", err)
	}

	// Publish JWT authority
	resp, err := p.serverClient.publishJWTAuthority(stream.Context(), jwtKey)
	if err != nil {
		return err
	}

	var jwtKeys []*plugintypes.JWTKey
	for _, jwtKey := range resp {
		pluginKey, err := jwtkey.ToPluginFromAPIProto(jwtKey)
		if err != nil {
			return err
		}
		jwtKeys = append(jwtKeys, pluginKey)
	}

	// Set JWT authority
	p.setBundleJWTAuthorities(jwtKeys)

	keys := []*plugintypes.JWTKey{}
	ticker := clk.Ticker(internalPollFreq)
	defer ticker.Stop()
	for {
		newKeys := p.getBundle().JwtAuthorities
		// Send response when new JWT authority
		if !arePublicKeysEqual(keys, newKeys) {
			keys = newKeys
			err := stream.Send(&upstreamauthorityv1.PublishJWTKeyResponse{
				UpstreamJwtKeys: keys,
			})
			if err != nil {
				p.log.Error("Cannot send upstream JWT keys", "error", err)
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

func (p *Plugin) pollBundleUpdates(ctx context.Context) {
	ticker := clk.Ticker(upstreamPollFreq)
	defer ticker.Stop()
	for {
		preFetchCallVersion := p.getBundleVersion()
		resp, err := p.serverClient.getBundle(ctx)
		if err != nil {
			p.log.Warn("Failed to fetch bundle while polling", "error", err)
		} else {
			err := p.setBundleIfVersionMatches(resp, preFetchCallVersion)
			if err != nil {
				p.log.Warn("Failed to set bundle while polling", "error", err)
			}
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			p.serverClient.release()
			p.log.Debug("Poll bundle updates context done", "reason", ctx.Err())
			return
		}
	}
}

func (p *Plugin) setBundleIfVersionMatches(b *types.Bundle, expectedVersion uint64) error {
	p.bundleMtx.Lock()
	defer p.bundleMtx.Unlock()

	if p.bundleVersion == expectedVersion {
		currentBundle, err := bundle.ToPluginFromAPIProto(b)
		if err != nil {
			return err
		}
		p.currentBundle = currentBundle
	}

	return nil
}

func (p *Plugin) getBundle() *plugintypes.Bundle {
	p.bundleMtx.RLock()
	defer p.bundleMtx.RUnlock()
	return p.currentBundle
}

func (p *Plugin) setBundleJWTAuthorities(keys []*plugintypes.JWTKey) {
	p.bundleMtx.Lock()
	defer p.bundleMtx.Unlock()
	p.currentBundle.JwtAuthorities = keys
	p.bundleVersion++
}

func (p *Plugin) setBundleX509Authorities(rootCAs []*plugintypes.X509Certificate) {
	p.bundleMtx.Lock()
	defer p.bundleMtx.Unlock()
	p.currentBundle.X509Authorities = rootCAs
	p.bundleVersion++
}

func (p *Plugin) getBundleVersion() uint64 {
	p.bundleMtx.RLock()
	defer p.bundleMtx.RUnlock()
	return p.bundleVersion
}

func (p *Plugin) subscribeToPolling(streamCtx context.Context) error {
	p.pollMtx.Lock()
	defer p.pollMtx.Unlock()
	if p.currentPollSubscribers == 0 {
		if err := p.startPolling(streamCtx); err != nil {
			return err
		}
	}
	p.currentPollSubscribers++
	return nil
}

func (p *Plugin) unsubscribeToPolling() {
	p.pollMtx.Lock()
	defer p.pollMtx.Unlock()
	p.currentPollSubscribers--
	if p.currentPollSubscribers == 0 {
		// TODO: may we release server here?
		p.stopPolling()
	}
}

func (p *Plugin) startPolling(streamCtx context.Context) error {
	var pollCtx context.Context
	pollCtx, p.stopPolling = context.WithCancel(context.Background())

	if err := p.serverClient.start(streamCtx); err != nil {
		return err
	}

	go p.pollBundleUpdates(pollCtx)
	return nil
}

func areRootsEqual(a, b []*plugintypes.X509Certificate) bool {
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

func arePublicKeysEqual(a, b []*plugintypes.JWTKey) bool {
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
