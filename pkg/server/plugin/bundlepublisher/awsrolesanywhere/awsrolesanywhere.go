package awsrolesanywhere

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rolesanywhere"
	rolesanywheretypes "github.com/aws/aws-sdk-go-v2/service/rolesanywhere/types"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk/support/bundleformat"
	bundlepublisherv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/bundlepublisher/v1"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	pluginName = "aws_rolesanywhere_trustanchor"
)

type pluginHooks struct {
	newRolesAnywhereClientFunc func(c aws.Config) (rolesAnywhere, error)
}

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func New() *Plugin {
	return newPlugin(newRolesAnywhereClient)
}

// Config holds the configuration of the plugin.
type Config struct {
	AccessKeyID     string `hcl:"access_key_id" json:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key" json:"secret_access_key"`
	Region          string `hcl:"region" json:"region"`
	TrustAnchorName string `hcl:"trust_anchor_name" json:"trust_anchor_name"`
}

// Plugin is the main representation of this bundle publisher plugin.
type Plugin struct {
	bundlepublisherv1.UnsafeBundlePublisherServer
	configv1.UnsafeConfigServer

	config    *Config
	configMtx sync.RWMutex

	bundle    *types.Bundle
	bundleMtx sync.RWMutex

	hooks               pluginHooks
	rolesAnywhereClient rolesAnywhere
	log                 hclog.Logger
}

// SetLogger sets a logger in the plugin.
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Configure configures the plugin.
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config, err := parseAndValidateConfig(req.HclConfiguration)
	if err != nil {
		return nil, err
	}

	awsCfg, err := newAWSConfig(ctx, config)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create client configuration: %v", err)
	}
	rolesAnywhere, err := p.hooks.newRolesAnywhereClientFunc(awsCfg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create client: %v", err)
	}
	p.rolesAnywhereClient = rolesAnywhere

	p.setConfig(config)
	p.setBundle(nil)
	return &configv1.ConfigureResponse{}, nil
}

// PublishBundle puts the bundle in the first Roles Anywhere trust anchor
// found with the configured name. If one doesn't exist, it is created.
func (p *Plugin) PublishBundle(ctx context.Context, req *bundlepublisherv1.PublishBundleRequest) (*bundlepublisherv1.PublishBundleResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	if req.Bundle == nil {
		return nil, status.Error(codes.InvalidArgument, "missing bundle in request")
	}

	currentBundle := p.getBundle()
	if proto.Equal(req.GetBundle(), currentBundle) {
		// Bundle not changed. No need to publish.
		return &bundlepublisherv1.PublishBundleResponse{}, nil
	}

	formatter := bundleformat.NewFormatter(req.GetBundle())
	bundleBytes, err := formatter.Format(bundleformat.PEM)
	bundleStr := string(bundleBytes)

	// Check whether there already exists a trust anchor with the name requested
	// If so, perform an update of its trust bundle
	var trustAnchor rolesanywheretypes.TrustAnchorDetail
	foundTrustAnchor := false
	prevNextToken := ""
	for ok := true; ok; {
		// List trust anchors
		listTrustAnchorsInput := rolesanywhere.ListTrustAnchorsInput{}
		if prevNextToken != "" {
			listTrustAnchorsInput.NextToken = &prevNextToken
		}
		listTrustAnchorsOutput, err := p.rolesAnywhereClient.ListTrustAnchors(ctx, &listTrustAnchorsInput)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to list trust anchors: %v", err)
		}

		// Iterate through trust anchors in response
		for _, curTrustAnchor := range listTrustAnchorsOutput.TrustAnchors {
			if *curTrustAnchor.Name == config.TrustAnchorName {
				trustAnchor = curTrustAnchor
				foundTrustAnchor = true
				break
			}
		}

		if foundTrustAnchor {
			break
		}

		if listTrustAnchorsOutput.NextToken == nil {
			break
		}
		prevNextToken = *listTrustAnchorsOutput.NextToken
	}

	trustAnchorArn := ""
	if foundTrustAnchor {
		// Update the trust anchor that was found
		updateTrustAnchorInput := rolesanywhere.UpdateTrustAnchorInput{
			TrustAnchorId: trustAnchor.TrustAnchorId,
			Source: &rolesanywheretypes.Source{
				SourceType: rolesanywheretypes.TrustAnchorTypeCertificateBundle,
				SourceData: &rolesanywheretypes.SourceDataMemberX509CertificateData{
					Value: bundleStr,
				},
			},
		}
		updateTrustAnchorOutput, err := p.rolesAnywhereClient.UpdateTrustAnchor(ctx, &updateTrustAnchorInput)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to update trust anchor: %v", err)
		}
		trustAnchorArn = *updateTrustAnchorOutput.TrustAnchor.TrustAnchorArn
	} else {
		// Create a new trust anchor, since an existing one with the requsted name couldn't be found
		createTrustAnchorInput := rolesanywhere.CreateTrustAnchorInput{
			Name: &config.TrustAnchorName,
			Source: &rolesanywheretypes.Source{
				SourceType: rolesanywheretypes.TrustAnchorTypeCertificateBundle,
				SourceData: &rolesanywheretypes.SourceDataMemberX509CertificateData{
					Value: bundleStr,
				},
			},
			Enabled: func() *bool { b := true; return &b }(),
		}

		createTrustAnchorOutput, err := p.rolesAnywhereClient.CreateTrustAnchor(ctx, &createTrustAnchorInput)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create trust anchor: %v", err)
		}
		trustAnchorArn = *createTrustAnchorOutput.TrustAnchor.TrustAnchorArn
	}

	p.setBundle(req.GetBundle())
	p.log.Debug("Trust anchor bundle updated", "ARN", trustAnchorArn)
	return &bundlepublisherv1.PublishBundleResponse{}, nil
}

// getBundle gets the latest bundle that the plugin has.
func (p *Plugin) getBundle() *types.Bundle {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()

	return p.bundle
}

// getConfig gets the configuration of the plugin.
func (p *Plugin) getConfig() (*Config, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()

	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

// setBundle updates the current bundle in the plugin with the provided bundle.
func (p *Plugin) setBundle(bundle *types.Bundle) {
	p.bundleMtx.Lock()
	defer p.bundleMtx.Unlock()

	p.bundle = bundle
}

// setConfig sets the configuration for the plugin.
func (p *Plugin) setConfig(config *Config) {
	p.configMtx.Lock()
	defer p.configMtx.Unlock()

	p.config = config
}

// builtin creates a new BundlePublisher built-in plugin.
func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		bundlepublisherv1.BundlePublisherPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// newPlugin returns a new plugin instance.
func newPlugin(newRolesAnywhereClientFunc func(c aws.Config) (rolesAnywhere, error)) *Plugin {
	return &Plugin{
		hooks: pluginHooks{
			newRolesAnywhereClientFunc: newRolesAnywhereClientFunc,
		},
	}
}

// parseAndValidateConfig returns an error if any configuration provided does
// not meet acceptable criteria
func parseAndValidateConfig(c string) (*Config, error) {
	config := new(Config)

	if err := hcl.Decode(config, c); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if config.Region == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is missing the region")
	}

	if config.TrustAnchorName == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration is missing the trust anchor name")
	}
	return config, nil
}
