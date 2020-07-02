package main

import (
	"context"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/zeebo/errs"
)

const (
	// TODO: Replace with your plugin name. This will be used by the catalog to
	// identify your plugin. Plugin names don't usually contain the plugin type
	// in them. For example, prefer "my-plugin" to "my-plugin-node-attestor".
	pluginName = "my-plugin"
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
	return catalog.MakePlugin(pluginName, nodeattestor.PluginServer(p))
}

type Config struct {
	// TODO: fill in configurables you want to be able to control from the
	// HCL configuration file.
	//
	// For example,
	// SomeValue string `hcl:"some_value"`
}

type Plugin struct {
	// mu is a mutex that protects the configuration. Plugins may at some point
	// need to support hot-reloading of configuration (by receiving another
	// call to Configure). So we need to prevent the configuration from
	// being used concurrently and make sure it is updated atomically.
	mu sync.Mutex
	c  *Config
}

// These are compile time assertions that the plugin matches the interfaces the
// catalog requires to provide the plugin with a logger and host service
// broker.
var _ catalog.NeedsLogger = (*Plugin)(nil)
var _ catalog.NeedsHostServices = (*Plugin)(nil)

func New() *Plugin {
	return &Plugin{}
}

// SetLogger will be called by the catalog system to provide the plugin with
// a logger when it is loaded. The logger is wired up to the SPIRE core
// logger
func (p *Plugin) SetLogger(log hclog.Logger) {
	// TODO: store the logger for later use. If the plugin does not need to
	// log, this method can be removed.
}

// BrokerHostServices is called by the catalog system when the plugin is loaded
// to provide it with host services implemented by SPIRE core.
func (p *Plugin) BrokerHostServices(broker catalog.HostServiceBroker) error {
	// TODO: use the broker to obtain clients to host services needed by the
	// plugin for later use. If the plugin does not need any host services,
	// this method can be removed.
	return nil
}

// FetchAttestationData is called by the agent when initiating node attestation.
// The agent acts as a conduit between this plugin and the corresponding
// node attestor plugin on the server.
//
// FetchAttestationData should do the following:
//   1) Gather attestation data
//   2) Send the attestation data through the stream
// If implementing a challenge response flow, the plugin should then:
//   3) Receive a challenge from the server
//   4) Send a challenge response back to the server
//   5) Repeat 3 and 4 as much as necessary to complete the challenge/response.
func (p *Plugin) FetchAttestationData(stream nodeattestor.NodeAttestor_FetchAttestationDataServer) (err error) {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	data, err := p.loadAttestationData(stream.Context(), config)
	if err != nil {
		return err
	}

	// Send the attestation data back to the agent. The "type" of the
	// attestation data should be set to the plugin name.
	if err := stream.Send(&nodeattestor.FetchAttestationDataResponse{
		AttestationData: &common.AttestationData{
			Type: pluginName,
			Data: data,
		},
	}); err != nil {
		return err
	}

	// TODO: Implement challenge response flow if necessary for your
	// attestation design.

	return nil
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
	// TODO: optionally fill out the plugin info. This is currently unused
	// by SPIRE.
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

func (p *Plugin) loadAttestationData(ctx context.Context, config *Config) ([]byte, error) {
	// TODO: gather the attestation data using any necessary values the
	// configuration
	var attestationData []byte

	return attestationData, nil
}

// TODO: If you are implementing an external plugin, you can use the following main()
// to run your plugin. If this is a builtin plugin, the catalog can use the
// BuiltIn() function in this package to load the plugin and this function can
// be removed.
func main() {
	catalog.PluginMain(BuiltIn())
}
