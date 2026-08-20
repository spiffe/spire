package cmp

import (
	"context"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// This compile-time assertion ensures the plugin conforms properly to the
	// pluginsdk.NeedsLogger interface.
	_ pluginsdk.NeedsLogger = (*Plugin)(nil)
)

const (
	pluginName = "cmp"
)

// Plugin implements the UpstreamAuthority plugin.
type Plugin struct {
	upstreamauthorityv1.UnimplementedUpstreamAuthorityServer
	configv1.UnimplementedConfigServer

	configMtx sync.RWMutex
	config    *Config
	logger    hclog.Logger
}

// BuiltIn constructs a catalog.BuiltIn using a new instance of this plugin.
func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

// builtin constructs the plugin catalog entry for the CMP upstream authority.
func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		upstreamauthorityv1.UpstreamAuthorityPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// Config defines the configuration for the plugin.
type Config struct {
	Hostname          string `hcl:"hostname" json:"hostname"`
	CACertPath        string `hcl:"ca_cert_path" json:"ca_cert_path"`
	ClientCertPath    string `hcl:"client_cert_path" json:"client_cert_path"`
	ClientCertKeyPath string `hcl:"client_cert_key_path" json:"client_cert_key_path"`
}

func buildConfig(_ catalog.CoreConfig, hclText string, status *pluginconf.Status) *Config {
	newConfig := new(Config)
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportError("plugin configuration is malformed")
		return nil
	}

	if newConfig.Hostname == "" {
		status.ReportError("hostname is required")
	}

	return newConfig
}

// New returns an instantiated CMP UpstreamAuthority plugin.
func New() *Plugin {
	return &Plugin{}
}

// SetLogger is called by the framework when the plugin is loaded and provides
// the plugin with a logger wired up to SPIRE's logging facilities.
func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

// Configure configures the CMP UpstreamAuthority plugin. This is invoked by SPIRE when the plugin is
// first loaded. After the first invocation, it may be used to reconfigure the plugin.
func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	p.setConfig(newConfig)
	return &configv1.ConfigureResponse{}, nil
}

// Validate validates the CMP UpstreamAuthority plugin configuration.
func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

// MintX509CAAndSubscribe implements the UpstreamAuthority MintX509CAAndSubscribe RPC.
// This plugin is a stub, so the call fails once the plugin is known to be configured and
// will keep doing so until the CMP certificate issuance flow is implemented.
func (p *Plugin) MintX509CAAndSubscribe(*upstreamauthorityv1.MintX509CARequest, upstreamauthorityv1.UpstreamAuthority_MintX509CAAndSubscribeServer) error {
	if _, err := p.getConfig(); err != nil {
		return err
	}

	return status.Error(codes.Unimplemented, "CMP upstreamauthority is not implemented")
}

// PublishJWTKeyAndSubscribe is not implemented by the CMP upstreamauthority plugin.
func (*Plugin) PublishJWTKeyAndSubscribe(*upstreamauthorityv1.PublishJWTKeyRequest, upstreamauthorityv1.UpstreamAuthority_PublishJWTKeyAndSubscribeServer) error {
	return status.Error(codes.Unimplemented, "publishing JWT keys is not supported by the CMP upstreamauthority plugin")
}

// SubscribeToLocalBundle is not implemented by the CMP upstreamauthority plugin.
func (*Plugin) SubscribeToLocalBundle(*upstreamauthorityv1.SubscribeToLocalBundleRequest, upstreamauthorityv1.UpstreamAuthority_SubscribeToLocalBundleServer) error {
	return status.Error(codes.Unimplemented, "fetching upstream trust bundle is unsupported")
}

func (p *Plugin) setConfig(config *Config) {
	p.configMtx.Lock()
	p.config = config
	p.configMtx.Unlock()
}

func (p *Plugin) getConfig() (*Config, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "cmp upstreamauthority is not configured")
	}
	return p.config, nil
}
