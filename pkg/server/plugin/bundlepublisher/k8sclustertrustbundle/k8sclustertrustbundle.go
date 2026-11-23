package k8sclustertrustbundle

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk/support/bundleformat"
	bundlepublisherv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/bundlepublisher/v1"
	"github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	pluginName = "k8s_clustertrustbundle"
)

type pluginHooks struct {
	newK8sClientFunc func(string) (kubernetesClient, error)
}

// BuiltIn returns a new BundlePublisher built-in plugin.
func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

// New creates a new k8s_clustertrustbundle BundlePublisher plugin instance.
func New() *Plugin {
	return newPlugin(newK8sClient)
}

// Config holds the configuration of the plugin.
type Config struct {
	Clusters map[string]*Cluster `hcl:"clusters,block" json:"clusters"`
}

// Cluster holds the configuration for a single Kubernetes cluster.
type Cluster struct {
	ClusterTrustBundleName string `hcl:"cluster_trust_bundle_name" json:"cluster_trust_bundle_name"`
	SignerName             string `hcl:"signer_name" json:"signer_name"`
	KubeConfigPath         string `hcl:"kubeconfig_path" json:"kubeconfig_path"`

	// k8sClient is the Kubernetes client used to interact with the cluster, set
	// when the plugin is configured.
	k8sClient kubernetesClient
}

// buildConfig builds the plugin configuration from the provided HCL config.
func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *Config {
	newConfig := new(Config)

	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	if len(newConfig.Clusters) == 0 {
		status.ReportInfo("No clusters configured, bundle will not be published")
	}

	for id, cluster := range newConfig.Clusters {
		if cluster.ClusterTrustBundleName == "" {
			status.ReportErrorf("missing cluster trust bundle name in cluster %q", id)
			return nil
		}
		// The API server requires the object name to be prefixed with the
		// signer name, with slashes translated to colons, and rejects colons
		// in the name of a ClusterTrustBundle without a signer name.
		if cluster.SignerName != "" {
			prefix := strings.ReplaceAll(cluster.SignerName, "/", ":") + ":"
			if !strings.HasPrefix(cluster.ClusterTrustBundleName, prefix) {
				status.ReportErrorf("cluster trust bundle name %q in cluster %q must have the prefix %q when signer_name is set", cluster.ClusterTrustBundleName, id, prefix)
				return nil
			}
		} else if strings.Contains(cluster.ClusterTrustBundleName, ":") {
			status.ReportErrorf("cluster trust bundle name %q in cluster %q must not contain \":\" when signer_name is not set", cluster.ClusterTrustBundleName, id)
			return nil
		}
	}

	return newConfig
}

// Plugin is the main representation of this bundle publisher plugin.
type Plugin struct {
	bundlepublisherv1.UnsafeBundlePublisherServer
	configv1.UnsafeConfigServer

	config    *Config
	configMtx sync.RWMutex

	bundle    *types.Bundle
	bundleMtx sync.RWMutex

	hooks pluginHooks
	log   hclog.Logger
}

// SetLogger sets a logger in the plugin.
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Configure configures the plugin.
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, notes, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}
	for _, note := range notes {
		p.log.Warn(note)
	}

	for id := range newConfig.Clusters {
		k8sClient, err := p.hooks.newK8sClientFunc(newConfig.Clusters[id].KubeConfigPath)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create Kubernetes client for cluster %q: %v", id, err)
		}
		newConfig.Clusters[id].k8sClient = k8sClient
	}

	p.setConfig(newConfig)
	p.setBundle(nil)
	return &configv1.ConfigureResponse{}, nil
}

// PublishBundle puts the X.509 authorities of the bundle in the configured
// Kubernetes ClusterTrustBundle.
func (p *Plugin) PublishBundle(ctx context.Context, req *bundlepublisherv1.PublishBundleRequest) (*bundlepublisherv1.PublishBundleResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	if req.Bundle == nil {
		return nil, status.Error(codes.InvalidArgument, "missing bundle in request")
	}

	currentBundle := p.getBundle()
	if proto.Equal(req.Bundle, currentBundle) {
		// Bundle not changed. No need to publish.
		return &bundlepublisherv1.PublishBundleResponse{}, nil
	}

	// The API server rejects a ClusterTrustBundle with an empty trust bundle.
	if len(req.Bundle.X509Authorities) == 0 {
		return nil, status.Error(codes.InvalidArgument, "bundle has no X.509 authorities")
	}

	bundleBytes, err := bundleformat.NewFormatter(req.Bundle).Format(bundleformat.PEM)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not format bundle: %v", err)
	}

	var allErrors error
	for id, cluster := range config.Clusters {
		log := p.log.With(
			"cluster_id", id,
			"kubeconfig_path", cluster.KubeConfigPath,
			"cluster_trust_bundle", cluster.ClusterTrustBundleName,
			"signer_name", cluster.SignerName,
		)

		if err := cluster.k8sClient.ApplyClusterTrustBundle(ctx, cluster, bundleBytes); err != nil {
			allErrors = errors.Join(allErrors, fmt.Errorf("failed to apply ClusterTrustBundle for cluster %q: %w", id, err))
			continue
		}

		log.Debug("Bundle published to Kubernetes ClusterTrustBundle")
	}

	if allErrors != nil {
		return nil, status.Error(codes.Internal, allErrors.Error())
	}

	p.setBundle(req.Bundle)
	return &bundlepublisherv1.PublishBundleResponse{}, nil
}

// Validate validates the configuration of the plugin.
func (p *Plugin) Validate(ctx context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

// getBundle gets the latest bundle that the plugin has.
func (p *Plugin) getBundle() *types.Bundle {
	p.bundleMtx.RLock()
	defer p.bundleMtx.RUnlock()

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
func newPlugin(newK8sClientFunc func(string) (kubernetesClient, error)) *Plugin {
	return &Plugin{
		hooks: pluginHooks{
			newK8sClientFunc: newK8sClientFunc,
		},
	}
}
