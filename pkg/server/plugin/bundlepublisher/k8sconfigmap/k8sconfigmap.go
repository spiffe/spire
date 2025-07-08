package k8sconfigmap

import (
	"context"
	"errors"
	"fmt"
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
	pluginName = "k8s_configmap"
)

type pluginHooks struct {
	newK8sClientFunc func(string) (kubernetesClient, error)
}

// BuiltIn returns a new BundlePublisher built-in plugin.
func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

// New creates a new k8s_configmap BundlePublisher plugin instance.
func New() *Plugin {
	return newPlugin(newK8sClient)
}

// Config holds the configuration of the plugin.
type Config struct {
	Clusters map[string]*Cluster `hcl:"clusters,block" json:"clusters"`
}

// Config holds the configuration of the plugin.
type Cluster struct {
	Format         string `hcl:"format" json:"format"`
	Namespace      string `hcl:"namespace" json:"namespace"`
	ConfigMapName  string `hcl:"configmap_name" json:"configmap_name"`
	ConfigMapKey   string `hcl:"configmap_key" json:"configmap_key"`
	KubeConfigPath string `hcl:"kubeconfig_path" json:"kubeconfig_path"`

	// bundleFormat is used to store the content of BundleFormat, parsed
	// as bundleformat.Format.
	bundleFormat bundleformat.Format

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
		if cluster.Format == "" {
			status.ReportErrorf("missing bundle format in cluster %q", id)
			return nil
		}
		if cluster.Namespace == "" {
			status.ReportErrorf("missing namespace in cluster %q", id)
			return nil
		}
		if cluster.ConfigMapName == "" {
			status.ReportErrorf("missing configmap name in cluster %q", id)
			return nil
		}
		if cluster.ConfigMapKey == "" {
			status.ReportErrorf("missing configmap key in cluster %q", id)
			return nil
		}
		bundleFormat, err := bundleformat.FromString(cluster.Format)
		if err != nil {
			status.ReportErrorf("could not parse bundle format from cluster %q: %v", id, err)
			return nil
		}

		switch bundleFormat {
		case bundleformat.JWKS:
		case bundleformat.SPIFFE:
		case bundleformat.PEM:
		default:
			status.ReportErrorf("bundle format %q is not supported", cluster.Format)
			return nil
		}
		cluster.bundleFormat = bundleFormat
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

// PublishBundle puts the bundle in the configured Kubernetes ConfigMap.
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

	formatter := bundleformat.NewFormatter(req.Bundle)

	var allErrors error
	for id, cluster := range config.Clusters {
		bundleBytes, err := formatter.Format(cluster.bundleFormat)
		if err != nil {
			allErrors = errors.Join(allErrors, fmt.Errorf("could not format bundle when publishing to cluster %q: %w", id, err))
			continue
		}

		log := p.log.With(
			"cluster_id", id,
			"format", cluster.bundleFormat,
			"kubeconfig_path", cluster.KubeConfigPath,
			"namespace", cluster.Namespace,
			"configmap", cluster.ConfigMapName,
			"key", cluster.ConfigMapKey,
		)

		if err := cluster.k8sClient.ApplyConfigMap(ctx, cluster, bundleBytes); err != nil {
			allErrors = errors.Join(allErrors, fmt.Errorf("failed to apply ConfigMap for cluster %q: %w", id, err))
			continue
		}

		log.Debug("Bundle published to Kubernetes ConfigMap")
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
	}, err
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
