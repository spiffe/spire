package k8sbootstrapper

import (
	"bytes"
	"context"
	"encoding/pem"
	"net/http"
	"sync"

	"github.com/hashicorp/hcl"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/bootstrapper"
	"github.com/zeebo/errs"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	bootstrapErr = errs.Class("k8s-bootstrapper")
)

const (
	defaultNamespace    = "spire"
	defaultConfigMap    = "spire-bootstrap"
	defaultConfigMapKey = "bootstrap.crt"
)

type ConfigUpdaterConfig struct {
	Namespace          string `hcl:"namespace"`
	ConfigMap          string `hcl:"config_map"`
	ConfigMapKey       string `hcl:"config_map_key"`
	KubeConfigFilePath string `hcl:"kube_config_file_path"`
}

type K8SBootstrapPlugin struct {
	mu     sync.RWMutex
	config *ConfigUpdaterConfig

	hooks struct {
		newClient func(configPath string) (kubeClient, error)
	}
}

var _ bootstrapper.Plugin = (*K8SBootstrapPlugin)(nil)

func New() *K8SBootstrapPlugin {
	p := &K8SBootstrapPlugin{}
	p.hooks.newClient = newClient
	return p
}

func (p *K8SBootstrapPlugin) PublishBundle(stream bootstrapper.PublishBundle_PluginStream) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	client, err := p.hooks.newClient(config.KubeConfigFilePath)
	if err != nil {
		return err
	}

	for {
		// Get the config map so we can use the version to resolve conflicts racing
		// on updates from other servers.
		configMap, err := client.GetConfigMap(stream.Context(), config.Namespace, config.ConfigMap)
		if err != nil {
			return bootstrapErr.New("unable to get config map %s/%s: %v", config.Namespace, config.ConfigMap, err)
		}

		// Signal the caller that we are ready for the bundle
		if err := stream.Send(&bootstrapper.PublishBundleResponse{}); err != nil {
			return err
		}

		// Receive the bundle
		req, err := stream.Recv()
		if err != nil {
			return err
		}
		if req.Bundle == nil {
			return bootstrapErr.New("request missing bundle")
		}
		bundle := req.Bundle

		// PEM encode all of the root CA certificates in the bundle
		bundleData := new(bytes.Buffer)
		for _, rootCA := range bundle.RootCas {
			pem.Encode(bundleData, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: rootCA.DerBytes,
			})
		}

		// Replace the config map data
		configMap.Data = map[string]string{
			config.ConfigMapKey: bundleData.String(),
		}

		// Update the bundle, handling version conflicts
		if err := client.UpdateConfigMap(stream.Context(), config.Namespace, configMap); err != nil {
			if s, ok := err.(k8serrors.APIStatus); ok && s.Status().Code == http.StatusConflict {
				// Somebody beat us to the update. We need to go through the read-modify-write cycle
				// again.
				continue
			}
			return bootstrapErr.New("unable to update config map %s/%s: %v", config.Namespace, config.ConfigMap, err)
		}

		// The update was successful.
		return nil
	}
}

func (p *K8SBootstrapPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config := new(ConfigUpdaterConfig)
	if err := hcl.Decode(&config, req.Configuration); err != nil {
		return nil, bootstrapErr.New("unable to decode configuration: %v", err)
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

func (p *K8SBootstrapPlugin) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *K8SBootstrapPlugin) getConfig() (*ConfigUpdaterConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, bootstrapErr.New("not configured")
	}
	return p.config, nil
}

func (p *K8SBootstrapPlugin) setConfig(config *ConfigUpdaterConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = config
}

func newClient(configPath string) (kubeClient, error) {
	config, err := getKubeConfig(configPath)
	if err != nil {
		return nil, bootstrapErr.Wrap(err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, bootstrapErr.Wrap(err)
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
	UpdateConfigMap(ctx context.Context, namespace string, configMap *corev1.ConfigMap) error
}

type kubeClientset struct {
	*kubernetes.Clientset
}

func (c kubeClientset) GetConfigMap(ctx context.Context, namespace, configMap string) (*corev1.ConfigMap, error) {
	return c.CoreV1().ConfigMaps(namespace).Get(configMap, metav1.GetOptions{})
}

func (c kubeClientset) UpdateConfigMap(ctx context.Context, namespace string, configMap *corev1.ConfigMap) error {
	_, err := c.CoreV1().ConfigMaps(namespace).Update(configMap)
	return err
}
