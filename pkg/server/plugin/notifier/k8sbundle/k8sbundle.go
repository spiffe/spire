package k8sbundle

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/hostservices"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/zeebo/errs"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
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
	WebhookLabel       string `hcl:"webhook_label"`
	KubeConfigFilePath string `hcl:"kube_config_file_path"`
}

type Plugin struct {
	notifier.UnsafeNotifierServer

	mu               sync.RWMutex
	log              hclog.Logger
	config           *pluginConfig
	identityProvider hostservices.IdentityProvider
	cancelWatcher    func()

	hooks struct {
		newKubeClient func(c *pluginConfig) ([]kubeClient, error)
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

	if _, ok := req.Event.(*notifier.NotifyRequest_BundleUpdated); ok {
		// ignore the bundle presented in the request. see updateBundle for details on why.
		if err := p.updateBundles(ctx, config); err != nil {
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

	if _, ok := req.Event.(*notifier.NotifyAndAdviseRequest_BundleLoaded); ok {
		// ignore the bundle presented in the request. see updateBundle for details on why.
		if err := p.updateBundles(ctx, config); err != nil {
			return nil, err
		}
	}
	return &notifier.NotifyAndAdviseResponse{}, nil
}

func (p *Plugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (resp *spi.ConfigureResponse, err error) {
	if p.identityProvider == nil {
		return nil, errors.New("required IdentityProvider host service not available")
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

	return &spi.ConfigureResponse{}, p.setConfig(config)
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

func (p *Plugin) setConfig(config *pluginConfig) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = config

	// Start watcher to set CA Bundle in objects created after server has started
	if p.cancelWatcher != nil {
		p.cancelWatcher()
	}
	if config.WebhookLabel != "" {
		watcher, err := newBundleWatcher(p, config)
		if err != nil {
			return err
		}
		var wg sync.WaitGroup
		ctx, cancel := context.WithCancel(context.Background())
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := watcher.Watch(ctx); err != nil && !errors.Is(err, context.Canceled) {
				p.log.Error("Unable to watch: %v", err)
			}
		}()
		p.cancelWatcher = func() {
			cancel()
			wg.Wait()
		}
	}

	return nil
}

// updateBundles iterates through all the objects that need an updated CA bundle
func (p *Plugin) updateBundles(ctx context.Context, c *pluginConfig) (err error) {
	clients, err := p.hooks.newKubeClient(c)
	if err != nil {
		return err
	}

	var updateErrs string
	for _, client := range clients {
		list, err := client.GetList(ctx, c)
		if err != nil {
			return k8sErr.New("unable to get list: %v", err)
		}
		listItems, err := meta.ExtractList(list)
		if err != nil {
			return k8sErr.New("unable to extract list items: %v", err)
		}
		for _, item := range listItems {
			itemMeta, err := meta.Accessor(item)
			if err != nil {
				return err
			}
			if err := p.updateBundle(ctx, c, client, itemMeta.GetNamespace(), itemMeta.GetName()); err != nil {
				updateErrs += fmt.Sprintf("%s: %v, ", namespacedName(itemMeta), err)
			}
		}
	}

	if len(updateErrs) > 0 {
		return k8sErr.New("unable to update: %s", strings.TrimSuffix(updateErrs, ", "))
	}
	return nil
}

// updateBundle does the ready-modify-write semantics for Kubernetes, retrying on conflict
func (p *Plugin) updateBundle(ctx context.Context, c *pluginConfig, client kubeClient, namespace, name string) (err error) {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// Get the object so we can use the version to resolve conflicts racing
		// on updates from other servers.
		obj, err := client.Get(ctx, namespace, name)
		if err != nil {
			return k8sErr.New("unable to get object %s/%s: %v", namespace, name, err)
		}

		// Load bundle data from the registration api. The bundle has to be
		// loaded after fetching the object so we can properly detect and
		// correct a race updating the bundle (i.e.  read-modify-write
		// semantics).
		resp, err := p.identityProvider.FetchX509Identity(ctx, &hostservices.FetchX509IdentityRequest{})
		if err != nil {
			return err
		}

		// Build patch with the new bundle data. The resource version MUST be set
		// to support conflict resolution.
		patch, err := client.CreatePatch(ctx, c, obj, resp)
		if err != nil {
			return err
		}

		// Patch the bundle, handling version conflicts
		patchBytes, err := json.Marshal(patch)
		if err != nil {
			return k8sErr.New("unable to marshal patch: %v", err)
		}
		return client.Patch(ctx, namespace, name, patchBytes)
	})
}

func newKubeClient(c *pluginConfig) ([]kubeClient, error) {
	clientset, err := newKubeClientset(c.KubeConfigFilePath)
	if err != nil {
		return nil, k8sErr.Wrap(err)
	}

	clients := []kubeClient{configMapClient{Clientset: clientset}}
	if c.WebhookLabel != "" {
		clients = append(clients,
			mutatingWebhookClient{Clientset: clientset},
			validatingWebhookClient{Clientset: clientset},
		)
	}

	return clients, nil
}

func newKubeClientset(configPath string) (*kubernetes.Clientset, error) {
	config, err := getKubeConfig(configPath)
	if err != nil {
		return nil, k8sErr.Wrap(err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, k8sErr.Wrap(err)
	}
	return client, nil
}

func getKubeConfig(configPath string) (*rest.Config, error) {
	if configPath != "" {
		return clientcmd.BuildConfigFromFlags("", configPath)
	}
	return rest.InClusterConfig()
}

// kubeClient encapsulates the Kubenetes API for config maps, validating webhooks, and mutating webhooks
type kubeClient interface {
	Get(ctx context.Context, namespace, name string) (runtime.Object, error)
	GetList(ctx context.Context, config *pluginConfig) (runtime.Object, error)
	CreatePatch(ctx context.Context, config *pluginConfig, obj runtime.Object, resp *hostservices.FetchX509IdentityResponse) (runtime.Object, error)
	Patch(ctx context.Context, namespace, name string, patchBytes []byte) error
	Watch(ctx context.Context, config *pluginConfig) (watch.Interface, error)
}

// configMapClient encapsulates the Kubenetes API for updating the CA Bundle in a config map
type configMapClient struct {
	*kubernetes.Clientset
}

func (c configMapClient) Get(ctx context.Context, namespace, configMap string) (runtime.Object, error) {
	return c.CoreV1().ConfigMaps(namespace).Get(ctx, configMap, metav1.GetOptions{})
}

func (c configMapClient) GetList(ctx context.Context, config *pluginConfig) (runtime.Object, error) {
	obj, err := c.Get(ctx, config.Namespace, config.ConfigMap)
	if err != nil {
		return nil, err
	}
	configMap := obj.(*corev1.ConfigMap)
	return &corev1.ConfigMapList{
		Items: []corev1.ConfigMap{*configMap},
	}, nil
}

func (c configMapClient) CreatePatch(ctx context.Context, config *pluginConfig, obj runtime.Object, resp *hostservices.FetchX509IdentityResponse) (runtime.Object, error) {
	configMap, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return nil, k8sErr.New("wrong type, expecting config map")
	}
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			ResourceVersion: configMap.ResourceVersion,
		},
		Data: map[string]string{
			config.ConfigMapKey: bundleData(resp.Bundle),
		},
	}, nil
}

func (c configMapClient) Patch(ctx context.Context, namespace, name string, patchBytes []byte) error {
	_, err := c.CoreV1().ConfigMaps(namespace).Patch(ctx, name, types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{})
	return err
}

func (c configMapClient) Watch(ctx context.Context, config *pluginConfig) (watch.Interface, error) {
	return nil, nil
}

// mutatingWebhookClient encapsulates the Kubenetes API for updating the CA Bundle in a mutating webhook
type mutatingWebhookClient struct {
	*kubernetes.Clientset
}

func (c mutatingWebhookClient) Get(ctx context.Context, namespace, mutatingWebhook string) (runtime.Object, error) {
	return c.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, mutatingWebhook, metav1.GetOptions{})
}

func (c mutatingWebhookClient) GetList(ctx context.Context, config *pluginConfig) (runtime.Object, error) {
	return c.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=true", config.WebhookLabel),
	})
}

func (c mutatingWebhookClient) CreatePatch(ctx context.Context, config *pluginConfig, obj runtime.Object, resp *hostservices.FetchX509IdentityResponse) (runtime.Object, error) {
	mutatingWebhook, ok := obj.(*admissionv1.MutatingWebhookConfiguration)
	if !ok {
		return nil, k8sErr.New("wrong type, expecting mutating webhook")
	}

	patch := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			ResourceVersion: mutatingWebhook.ResourceVersion,
		},
	}
	patch.Webhooks = make([]admissionv1.MutatingWebhook, len(mutatingWebhook.Webhooks))

	// Step through all the the webhooks in the MutatingWebhookConfiguration
	for i := range patch.Webhooks {
		patch.Webhooks[i].AdmissionReviewVersions = mutatingWebhook.Webhooks[i].AdmissionReviewVersions
		patch.Webhooks[i].ClientConfig.CABundle = []byte(bundleData(resp.Bundle))
		patch.Webhooks[i].Name = mutatingWebhook.Webhooks[i].Name
		patch.Webhooks[i].SideEffects = mutatingWebhook.Webhooks[i].SideEffects
	}

	return patch, nil
}

func (c mutatingWebhookClient) Patch(ctx context.Context, namespace, name string, patchBytes []byte) error {
	_, err := c.AdmissionregistrationV1().MutatingWebhookConfigurations().Patch(ctx, name, types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{})
	return err
}

func (c mutatingWebhookClient) Watch(ctx context.Context, config *pluginConfig) (watch.Interface, error) {
	return c.AdmissionregistrationV1().MutatingWebhookConfigurations().Watch(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=true", config.WebhookLabel),
	})
}

// validatingWebhookClient encapsulates the Kubenetes API for updating the CA Bundle in a validating webhook
type validatingWebhookClient struct {
	*kubernetes.Clientset
}

func (c validatingWebhookClient) Get(ctx context.Context, namespace, validatingWebhook string) (runtime.Object, error) {
	return c.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, validatingWebhook, metav1.GetOptions{})
}

func (c validatingWebhookClient) GetList(ctx context.Context, config *pluginConfig) (runtime.Object, error) {
	return c.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=true", config.WebhookLabel),
	})
}

func (c validatingWebhookClient) CreatePatch(ctx context.Context, config *pluginConfig, obj runtime.Object, resp *hostservices.FetchX509IdentityResponse) (runtime.Object, error) {
	validatingWebhook, ok := obj.(*admissionv1.ValidatingWebhookConfiguration)
	if !ok {
		return nil, k8sErr.New("wrong type, expecting validating webhook")
	}

	patch := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			ResourceVersion: validatingWebhook.ResourceVersion,
		},
	}
	patch.Webhooks = make([]admissionv1.ValidatingWebhook, len(validatingWebhook.Webhooks))

	// Step through all the the webhooks in the ValidatingWebhookConfiguration
	for i := range patch.Webhooks {
		patch.Webhooks[i].AdmissionReviewVersions = validatingWebhook.Webhooks[i].AdmissionReviewVersions
		patch.Webhooks[i].ClientConfig.CABundle = []byte(bundleData(resp.Bundle))
		patch.Webhooks[i].Name = validatingWebhook.Webhooks[i].Name
		patch.Webhooks[i].SideEffects = validatingWebhook.Webhooks[i].SideEffects
	}

	return patch, nil
}

func (c validatingWebhookClient) Patch(ctx context.Context, namespace, name string, patchBytes []byte) error {
	_, err := c.AdmissionregistrationV1().ValidatingWebhookConfigurations().Patch(ctx, name, types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{})
	return err
}

func (c validatingWebhookClient) Watch(ctx context.Context, config *pluginConfig) (watch.Interface, error) {
	return c.AdmissionregistrationV1().ValidatingWebhookConfigurations().Watch(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=true", config.WebhookLabel),
	})
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

// namespacedName returns "namespace/name" for namespaced resources and "name" for non-namespaced resources
func namespacedName(itemMeta metav1.Object) string {
	if itemMeta.GetNamespace() != "" {
		return fmt.Sprintf("%s/%s", itemMeta.GetNamespace(), itemMeta.GetName())
	}
	return itemMeta.GetName()
}
