package tailscale

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/spiffe/spire/pkg/common/catalog"
	common "github.com/spiffe/spire/pkg/common/plugin/tailscale"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	nodeattestorbase "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/base"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
)

const (
	pluginName = "tailscale"

	// peerAddrMetadataKey is the gRPC metadata key used by the V1 wrapper
	// to forward the peer address from the OS TCP stack.
	peerAddrMetadataKey = "X-Forwarded-Peer-Addr"
)

// Tailscale CGNAT range: 100.64.0.0/10
var tailscaleCGNAT = netip.MustParsePrefix("100.64.0.0/10")

// Tailscale IPv6 range: fd7a:115c:a1e0::/48
var tailscaleIPv6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")

// whoisClient abstracts the Tailscale local API for testability.
type whoisClient interface {
	WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
}

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// Config is the HCL configuration for the plugin.
type Config struct {
	SocketPath        string `hcl:"socket_path"`
	AgentPathTemplate string `hcl:"agent_path_template"`
}

type configuration struct {
	trustDomain  spiffeid.TrustDomain
	socketPath   string
	pathTemplate *agentpathtemplate.Template
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *configuration {
	hclConfig := new(Config)
	if err := hcl.Decode(hclConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	pathTemplate := common.DefaultAgentPathTemplate
	if len(hclConfig.AgentPathTemplate) > 0 {
		tmpl, err := agentpathtemplate.Parse(hclConfig.AgentPathTemplate)
		if err != nil {
			status.ReportErrorf("failed to parse agent path template: %q", hclConfig.AgentPathTemplate)
		}
		pathTemplate = tmpl
	}

	return &configuration{
		trustDomain:  coreConfig.TrustDomain,
		socketPath:   hclConfig.SocketPath,
		pathTemplate: pathTemplate,
	}
}

// Plugin implements the server-side Tailscale node attestor using the local whois API.
type Plugin struct {
	nodeattestorbase.Base
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	config *configuration
	mtx    sync.Mutex
	log    hclog.Logger
	hooks  struct {
		newClient func(socketPath string) whoisClient
	}
}

func New() *Plugin {
	p := &Plugin{}
	p.hooks.newClient = func(socketPath string) whoisClient {
		c := &local.Client{}
		if socketPath != "" {
			c.Socket = socketPath
		}
		return c
	}
	return p
}

// SetLogger sets the plugin logger.
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Attest implements the server-side node attestation flow using the Tailscale
// local API (whois). The agent's identity is determined by looking up its
// Tailscale IP via the tailscaled daemon running on the server.
func (p *Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	// Step 1: Receive payload (just a marker, contents ignored)
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	if req.GetPayload() == nil {
		return status.Error(codes.InvalidArgument, "missing attestation payload")
	}

	// Step 2: Extract peer address from gRPC metadata
	peerAddr, err := peerAddrFromMetadata(stream.Context())
	if err != nil {
		return err
	}

	// Step 3: Validate it's a Tailscale IP
	if !isTailscaleIP(peerAddr) {
		return status.Errorf(codes.PermissionDenied, "peer address %s is not a Tailscale IP", peerAddr)
	}

	// Step 4: Call tailscaled whois API
	client := p.hooks.newClient(config.socketPath)
	whoisResp, err := client.WhoIs(stream.Context(), peerAddr)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to query tailscaled whois: %v", err)
	}

	if whoisResp.Node == nil {
		return status.Error(codes.Internal, "whois response missing node information")
	}

	// Step 5: Check device is authorized
	if !whoisResp.Node.MachineAuthorized {
		return status.Error(codes.PermissionDenied, "device is not authorized in tailnet")
	}

	// Step 6: Map whois response to DeviceInfo
	info := mapWhoIsToDeviceInfo(whoisResp)

	// Step 7: Construct SPIFFE ID
	agentID, err := common.MakeAgentID(config.trustDomain, config.pathTemplate, info)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create agent ID: %v", err)
	}

	// Step 8: TOFU check
	if err := p.AssessTOFU(stream.Context(), agentID.String(), p.log); err != nil {
		return err
	}

	// Step 9: Build selectors and return
	selectorValues := buildSelectorValues(&info)

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       agentID.String(),
				SelectorValues: selectorValues,
				CanReattest:    true,
			},
		},
	})
}

// Configure configures the plugin.
func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.config = newConfig

	return &configv1.ConfigureResponse{}, nil
}

// Validate validates the plugin configuration.
func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

func (p *Plugin) getConfig() (*configuration, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	if p.config == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

// peerAddrFromMetadata extracts the peer address from gRPC metadata set by the V1 wrapper.
func peerAddrFromMetadata(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Internal, "no gRPC metadata in context")
	}
	vals := md.Get(peerAddrMetadataKey)
	if len(vals) == 0 {
		return "", status.Error(codes.Internal, "peer address not found in gRPC metadata")
	}
	return vals[0], nil
}

// isTailscaleIP checks whether the given address (ip or ip:port) belongs to a
// Tailscale IP range.
func isTailscaleIP(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Might be just an IP without port
		host = addr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return tailscaleCGNAT.Contains(ip) || tailscaleIPv6.Contains(ip)
}

// mapWhoIsToDeviceInfo converts a WhoIsResponse into a DeviceInfo.
func mapWhoIsToDeviceInfo(resp *apitype.WhoIsResponse) common.DeviceInfo {
	node := resp.Node

	info := common.DeviceInfo{
		NodeID:     string(node.StableID),
		Hostname:   node.Hostinfo.Hostname(),
		OS:         node.Hostinfo.OS(),
		Authorized: node.MachineAuthorized,
	}

	// Tags
	for _, tag := range node.Tags {
		info.Tags = append(info.Tags, strings.TrimPrefix(tag, "tag:"))
	}

	// Addresses
	for _, addr := range node.Addresses {
		info.Addresses = append(info.Addresses, addr.Addr().String())
	}

	// User
	if resp.UserProfile != nil {
		info.User = resp.UserProfile.LoginName
	}

	return info
}

// buildSelectorValues builds selector values from device info.
func buildSelectorValues(info *common.DeviceInfo) []string {
	var selectors []string

	selectors = append(selectors, "hostname:"+info.Hostname)

	for _, tag := range info.Tags {
		selectors = append(selectors, "tag:"+tag)
	}

	if info.OS != "" {
		selectors = append(selectors, "os:"+info.OS)
	}

	for _, addr := range info.Addresses {
		selectors = append(selectors, "address:"+addr)
	}

	if info.User != "" {
		selectors = append(selectors, "user:"+info.User)
	}

	selectors = append(selectors, fmt.Sprintf("authorized:%t", info.Authorized))
	selectors = append(selectors, "node_id:"+info.NodeID)

	return selectors
}
