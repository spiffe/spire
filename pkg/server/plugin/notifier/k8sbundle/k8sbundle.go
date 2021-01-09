package k8sbundle

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
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
	"k8s.io/apimachinery/pkg/fields"
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

	mu                    sync.RWMutex
	log                   hclog.Logger
	config                *pluginConfig
	identityProvider      hostservices.IdentityProvider
	webhookWatcherStarted bool
	configUpdated         chan struct{}

	hooks struct {
		newKubeClient func(configPath string) ([]kubeClient, error)
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

	p.setConfig(config)

	// Start webhook watcher to set CA Bundle in webhooks created after server has started
	if config.WebhookLabel != "" {
		p.startOrUpdateWatchWebhooks(config)
	}
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

// updateBundles iterates through all the objects that need an updated CA bundle
func (p *Plugin) updateBundles(ctx context.Context, c *pluginConfig) (err error) {
	clients, err := p.hooks.newKubeClient(c.KubeConfigFilePath)
	if err != nil {
		return err
	}

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
				return k8sErr.New("unable to update %s/%s: %v", itemMeta.GetNamespace(), itemMeta.GetName(), err)
			}
		}
	}

	return nil
}

// updateBundle does the ready-modify-write semantics for Kubernetes, retrying on conflict
func (p *Plugin) updateBundle(ctx context.Context, c *pluginConfig, client kubeClient, namespace, name string) (err error) {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
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

		// Create patch with updated CA Bundles
		patch, err := client.CreatePatch(ctx, c, obj, resp)
		if err != nil {
			return err
		}

		// Patch the object
		patchBytes, err := json.Marshal(patch)
		if err != nil {
			return k8sErr.New("unable to marshal patch: %v", err)
		}
		return client.Patch(ctx, namespace, name, patchBytes)
	})
}

// startOrUpdateWatchWebhooks starts the webhook watcher or sends a signal to update configuration
func (p *Plugin) startOrUpdateWatchWebhooks(c *pluginConfig) {
	if !p.webhookWatcherStarted {
		p.webhookWatcherStarted = true
		p.configUpdated = make(chan struct{})
		go func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := p.watchWebhooks(ctx, c); err != nil {
				p.log.Error("watching webhooks", "error", err)
			}
			p.webhookWatcherStarted = false
		}()
	} else {
		p.configUpdated <- struct{}{}
	}
}

// watchWebhooks watches for new webhooks that are created with the configured label and updates the CA Bundle
func (p *Plugin) watchWebhooks(ctx context.Context, c *pluginConfig) (err error) {
	clients, err := p.hooks.newKubeClient(c.KubeConfigFilePath)
	if err != nil {
		return err
	}

	watchers, err := newWatchers(ctx, c, clients)
	if err != nil {
		return err
	}
	selectCase := p.newSelectCase(watchers)

	for {
		chosen, recv, _ := reflect.Select(selectCase)
		if chosen < len(clients) {
			if err = p.watchWebhookEvent(ctx, c, clients[chosen], recv.Interface().(watch.Event)); err != nil {
				p.log.Error("handling watch event for mutating webhook", "error", err)
			}
		} else {
			c, err = p.getConfig()
			if err != nil {
				p.log.Error("getting updated config", "error", err)
			}
			stopWatchers(watchers)
			watchers, err = newWatchers(ctx, c, clients)
			if err != nil {
				p.log.Error("getting updated webhook watchers", "error", err)
			}
			selectCase = p.newSelectCase(watchers)
		}
	}
}

// watchWebhookEvent triggers the read-modify-write for a newly created webhook
func (p *Plugin) watchWebhookEvent(ctx context.Context, c *pluginConfig, client kubeClient, event watch.Event) (err error) {
	if event.Type == watch.Added {
		webhookMeta, err := meta.Accessor(event.Object)
		if err != nil {
			return err
		}
		p.log.Debug("Setting bundle for new webhook", "name", webhookMeta.GetName())
		if err = p.updateBundle(ctx, c, client, webhookMeta.GetNamespace(), webhookMeta.GetName()); err != nil {
			return err
		}
	}
	return nil
}

func (p *Plugin) newSelectCase(watchers []watch.Interface) []reflect.SelectCase {
	selectCase := []reflect.SelectCase{}
	for _, watcher := range watchers {
		if watcher != nil {
			selectCase = append(selectCase, reflect.SelectCase{
				Dir:  reflect.SelectRecv,
				Chan: reflect.ValueOf(watcher.ResultChan()),
			})
		} else {
			selectCase = append(selectCase, reflect.SelectCase{
				Dir: reflect.SelectRecv,
			})
		}
	}
	selectCase = append(selectCase, reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(p.configUpdated),
	})
	return selectCase
}

func newWatchers(ctx context.Context, c *pluginConfig, clients []kubeClient) ([]watch.Interface, error) {
	watchers := []watch.Interface{}
	for _, client := range clients {
		watcher, err := client.Watch(ctx, c.WebhookLabel)
		if err != nil {
			return nil, err
		}
		watchers = append(watchers, watcher)
	}
	return watchers, nil
}

func stopWatchers(watchers []watch.Interface) {
	for _, watcher := range watchers {
		if watcher != nil {
			watcher.Stop()
		}
	}
}

func newKubeClient(configPath string) ([]kubeClient, error) {
	clientset, err := newKubeClientset(configPath)
	if err != nil {
		return nil, k8sErr.Wrap(err)
	}

	return []kubeClient{configMapClient{Clientset: clientset},
		mutatingWebhookClient{Clientset: clientset},
		validatingWebhookClient{Clientset: clientset}}, nil
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
	Watch(ctx context.Context, label string) (watch.Interface, error)
}

// configMapClient encapsulates the Kubenetes API for updating the CA Bundle in a config map
type configMapClient struct {
	*kubernetes.Clientset
}

func (c configMapClient) Get(ctx context.Context, namespace, configMap string) (runtime.Object, error) {
	return c.CoreV1().ConfigMaps(namespace).Get(ctx, configMap, metav1.GetOptions{})
}

func (c configMapClient) GetList(ctx context.Context, config *pluginConfig) (runtime.Object, error) {
	list, err := c.CoreV1().ConfigMaps(config.Namespace).List(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("metadata.name", config.ConfigMap).String(),
	})
	if err != nil {
		return nil, err
	}
	if len(list.Items) == 0 {
		return nil, k8sErr.New("unable to get config map %s/%s: not found", config.Namespace, config.ConfigMap)
	}
	return list, nil
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

func (c configMapClient) Watch(ctx context.Context, label string) (watch.Interface, error) {
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

func (c mutatingWebhookClient) Watch(ctx context.Context, label string) (watch.Interface, error) {
	return c.AdmissionregistrationV1().MutatingWebhookConfigurations().Watch(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=true", label),
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

func (c validatingWebhookClient) Watch(ctx context.Context, label string) (watch.Interface, error) {
	return c.AdmissionregistrationV1().ValidatingWebhookConfigurations().Watch(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=true", label),
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
