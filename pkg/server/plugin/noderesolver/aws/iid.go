package aws

import (
	"context"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/common/catalog"
	caws "github.com/spiffe/spire/pkg/common/plugin/aws"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	noderesolverv0 "github.com/spiffe/spire/proto/spire/plugin/server/noderesolver/v0"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *IIDResolverPlugin) catalog.Plugin {
	return catalog.MakePlugin(caws.PluginName,
		noderesolverv0.PluginServer(p),
	)
}

// IIDResolverPlugin implements node resolution for agents running in aws.
type IIDResolverPlugin struct {
	noderesolverv0.UnsafeNodeResolverServer

	log hclog.Logger
}

// New creates a new IIDResolverPlugin.
func New() *IIDResolverPlugin {
	return &IIDResolverPlugin{}
}

func (p *IIDResolverPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Configure configures the IIDResolverPlugin
func (p *IIDResolverPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	p.log.Warn("The aws_iid resolver has been subsumed by the aws_iid node attestor " +
		"and will be removed in a future release. Please remove it from your configuration.")
	return &spi.ConfigureResponse{}, nil
}

// GetPluginInfo returns the version and related metadata of the installed plugin.
func (p *IIDResolverPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

// Resolve handles the given resolve request
func (p *IIDResolverPlugin) Resolve(ctx context.Context, req *noderesolverv0.ResolveRequest) (*noderesolverv0.ResolveResponse, error) {
	return &noderesolverv0.ResolveResponse{}, nil
}
