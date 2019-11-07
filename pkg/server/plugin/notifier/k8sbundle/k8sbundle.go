package k8sbundle

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/hostservices"
	"github.com/spiffe/spire/proto/spire/server/notifier"
	"github.com/zeebo/errs"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	k8sErr = errs.Class("k8s-bundle")
)

const (
	defaultNamespace    = "spire"
	defaultConfigMap    = "spire-bundle"
	defaultConfigMapKey = "bundle.crt"
)

func BuiltIn() catalog.Plugin {
	return builtIn(New())
}

func builtIn(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin("k8sbundle",
		notifier.PluginServer(p),
	)
}

type pluginConfig struct {
	Namespace          string `hcl:"namespace"`
	ConfigMap          string `hcl:"config_map"`
	ConfigMapKey       string `hcl:"config_map_key"`
	KubeConfigFilePath string `hcl:"kube_config_file_path"`
}

type Plugin struct {
	mu               sync.RWMutex
	log              hclog.Logger
	config           *pluginConfig
	identityProvider hostservices.IdentityProvider

	hooks struct {
		newKubeClient func(configPath string) (kubeClient, error)
	}
}

func New() *Plugin {
	p := &Plugin{}
	p.hooks.newKubeClient = newKubeClient
	return p
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) BrokerHostServices(broker catalog.HostServiceBroker) error {
	has, err := broker.GetHostService(hostservices.IdentityProviderHostServiceClient(&p.identityProvider))
	if err != nil {
		return err
	}
	if !has {
		return k8sErr.New("IdentityProvider host service is required")
	}
	return nil
}

func (p *Plugin) Notify(ctx context.Context, req *notifier.NotifyRequest) (*notifier.NotifyResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	switch req.Event.(type) {
	case *notifier.NotifyRequest_BundleUpdated:
		// ignore the bundle presented in the request. see updateBundleConfigMap for details on why.
		if err := p.updateBundleConfigMap(ctx, config); err != nil {
			return nil, err
		}
	}
	return &notifier.NotifyResponse{}, nil
}

func (p *Plugin) NotifyAndAdvise(ctx context.Context, req *notifier.NotifyAndAdviseRequest) (*notifier.NotifyAndAdviseResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	switch req.Event.(type) {
	case *notifier.NotifyAndAdviseRequest_BundleLoaded:
		// ignore the bundle presented in the request. see updateBundleConfigMap for details on why.
		if err := p.updateBundleConfigMap(ctx, config); err != nil {
			return nil, err
		}
	}
	return &notifier.NotifyAndAdviseResponse{}, nil
}

func (p *Plugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (resp *spi.ConfigureResponse, err error) {
	if p.identityProvider == nil {
		return nil, errors.New("IdentityProvider host service is required but not brokered")
	}

	config := new(pluginConfig)
	if err := hcl.Decode(&config, req.Configuration); err != nil {
		return nil, k8sErr.New("unable to decode configuration: %v", err)
	}

	if config.Namespace == "" {
		config.Namespace = defaultNamespace
	}
	if config.ConfigMap == "" {
		config.ConfigMap = defaultConfigMap
	}
	if config.ConfigMapKey == "" {
		config.ConfigMapKey = defaultConfigMapKey
	}

	p.setConfig(config)
	return &spi.ConfigureResponse{}, nil
}

func (p *Plugin) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *Plugin) getConfig() (*pluginConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, k8sErr.New("not configured")
	}
	return p.config, nil
}

func (p *Plugin) setConfig(config *pluginConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = config
}

func (p *Plugin) updateBundleConfigMap(ctx context.Context, c *pluginConfig) (err error) {
	client, err := p.hooks.newKubeClient(c.KubeConfigFilePath)
	if err != nil {
		return err
	}

	for {
		// Get the config map so we can use the version to resolve conflicts racing
		// on updates from other servers.
		configMap, err := client.GetConfigMap(ctx, c.Namespace, c.ConfigMap)
		if err != nil {
			return k8sErr.New("unable to get config map %s/%s: %v", c.Namespace, c.ConfigMap, err)
		}

		// Load bundle data from the registration api. The bundle has to be
		// loaded after fetching the config map so we can properly detect and
		// correct a race updating the bundle (i.e.  read-modify-write
		// semantics).
		resp, err := p.identityProvider.FetchX509Identity(ctx, &hostservices.FetchX509IdentityRequest{})
		if err != nil {
			return err
		}

		// Build patch with the new bundle data. The resource version MUST be set
		// to support conflict resolution.
		patchBytes, err := json.Marshal(corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				ResourceVersion: configMap.ResourceVersion,
			},
			Data: map[string]string{
				c.ConfigMapKey: bundleData(resp.Bundle),
			},
		})
		if err != nil {
			return k8sErr.New("unable to marshal patch: %v", err)
		}

		// Patch the bundle, handling version conflicts
		if err := client.PatchConfigMap(ctx, c.Namespace, c.ConfigMap, patchBytes); err != nil {
			// If there is a conflict then some other server won the race updating
			// the ConfigMap. We need to retrieve the latest bundle and try again.
			if s, ok := err.(k8serrors.APIStatus); ok && s.Status().Code == http.StatusConflict {
				p.log.Debug("Conflict detected patching configmap; will retry", telemetry.VersionInfo, configMap.ResourceVersion)
				continue
			}
			return k8sErr.New("unable to update config map %s/%s: %v", c.Namespace, c.ConfigMap, err)
		}

		return nil
	}
}

func newKubeClient(configPath string) (kubeClient, error) {
	config, err := getKubeConfig(configPath)
	if err != nil {
		return nil, k8sErr.Wrap(err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, k8sErr.Wrap(err)
	}
	return kubeClientset{Clientset: client}, nil
}

func getKubeConfig(configPath string) (*rest.Config, error) {
	if configPath != "" {
		return clientcmd.BuildConfigFromFlags("", configPath)
	}
	return rest.InClusterConfig()
}

type kubeClient interface {
	GetConfigMap(ctx context.Context, namespace, configMap string) (*corev1.ConfigMap, error)
	PatchConfigMap(ctx context.Context, namespace string, configMap string, patchBytes []byte) error
}

type kubeClientset struct {
	*kubernetes.Clientset
}

func (c kubeClientset) GetConfigMap(ctx context.Context, namespace, configMap string) (*corev1.ConfigMap, error) {
	return c.CoreV1().ConfigMaps(namespace).Get(configMap, metav1.GetOptions{})
}

func (c kubeClientset) PatchConfigMap(ctx context.Context, namespace, configMap string, patchBytes []byte) error {
	_, err := c.CoreV1().ConfigMaps(namespace).Patch(configMap, types.StrategicMergePatchType, patchBytes)
	return err
}

// bundleData formats the bundle data for inclusion in the config map
func bundleData(bundle *common.Bundle) string {
	bundleData := new(bytes.Buffer)
	for _, rootCA := range bundle.RootCas {
		_ = pem.Encode(bundleData, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: rootCA.DerBytes,
		})
	}
	return bundleData.String()
}
