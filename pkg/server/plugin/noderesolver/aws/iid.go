package aws

import (
	"context"
	"os"
	"regexp"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/idutil"
	caws "github.com/spiffe/spire/pkg/common/plugin/aws"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/plugin/noderesolver"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
)

var (
	iidError = caws.IidErrorClass

	reAgentIDPath = regexp.MustCompile(`^/spire/agent/aws_iid/([^/]+)/([^/]+)/([^/]+)$`)
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *IIDResolverPlugin) catalog.Plugin {
	return catalog.MakePlugin(caws.PluginName,
		noderesolver.PluginServer(p),
	)
}

// IIDResolverPlugin implements node resolution for agents running in aws.
type IIDResolverPlugin struct {
	log     hclog.Logger
	clients *caws.ClientsCache

	hooks struct {
		getenv func(string) string
	}
}

// New creates a new IIDResolverPlugin.
func New() *IIDResolverPlugin {
	p := &IIDResolverPlugin{}
	p.hooks.getenv = os.Getenv
	p.clients = caws.NewClientsCache(caws.DefaultNewClientCallback)
	return p
}

func (p *IIDResolverPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Configure configures the IIDResolverPlugin
func (p *IIDResolverPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := new(caws.SessionConfig)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, iidError.New("unable to decode configuration: %w", err)
	}

	if err := config.Validate(p.hooks.getenv(caws.AccessKeyIDVarName), p.hooks.getenv(caws.SecretAccessKeyVarName)); err != nil {
		return nil, err
	}

	// set the AWS configuration and reset clients
	p.clients.Configure(*config)
	return &spi.ConfigureResponse{}, nil
}

// GetPluginInfo returns the version and related metadata of the installed plugin.
func (p *IIDResolverPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

// Resolve handles the given resolve request
func (p *IIDResolverPlugin) Resolve(ctx context.Context, req *noderesolver.ResolveRequest) (*noderesolver.ResolveResponse, error) {
	resp := &noderesolver.ResolveResponse{
		Map: make(map[string]*common.Selectors),
	}
	for _, spiffeID := range req.BaseSpiffeIdList {
		_, region, instanceID, err := parseAgentID(spiffeID)
		if err != nil {
			p.log.Warn("Unrecognized agent ID", telemetry.SPIFFEID, spiffeID)
			continue
		}

		awsClient, err := p.clients.GetClient(region)
		if err != nil {
			return nil, err
		}

		selectors, err := caws.ResolveSelectors(ctx, awsClient, instanceID)
		if err != nil {
			return nil, err
		}
		resp.Map[spiffeID] = selectors
	}
	return resp, nil
}

func parseAgentID(spiffeID string) (accountID, region, instanceID string, err error) {
	u, err := idutil.ParseSpiffeID(spiffeID, idutil.AllowAnyTrustDomainAgent())
	if err != nil {
		return "", "", "", iidError.New("unable to parse agent id %q: %w", spiffeID, err)
	}
	m := reAgentIDPath.FindStringSubmatch(u.Path)
	if m == nil {
		return "", "", "", iidError.New("malformed agent id %q", spiffeID)
	}
	return m[1], m[2], m[3], nil
}
