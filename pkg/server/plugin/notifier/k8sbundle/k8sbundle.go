package k8sbundle

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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
		newKubeClient func(configPath string) (*kubernetes.Clientset, error)
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
	client, err := p.hooks.newKubeClient(c.KubeConfigFilePath)
	if err != nil {
		return err
	}
	configMapClient, mutatingWebhookClient, validatingWebhookClient := newKubeClientsets(c, client)
	clientsets := []kubeClientset{configMapClient, mutatingWebhookClient, validatingWebhookClient}

	for _, clientset := range clientsets {
		list, err := clientset.GetList(ctx, c)
		if err != nil {
			return k8sErr.New("unable to get list:", err)
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
			if err := p.updateBundle(ctx, c, clientset, itemMeta.GetNamespace(), itemMeta.GetName()); err != nil {
				return err
			}
		}
	}

	return nil
}

// updateBundle does the ready-modify-write semantics for Kubernetes, retrying on conflict
func (p *Plugin) updateBundle(ctx context.Context, c *pluginConfig, client kubeClientset, namespace, name string) (err error) {
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
		return client.Patch(ctx, obj, patchBytes)
	})
}

// startOrUpdateWatchWebhooks starts the webhook watcher or sends a signal to update configuration
func (p *Plugin) startOrUpdateWatchWebhooks(c *pluginConfig) (err error) {
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
	return nil
}

// watchWebhooks watches for new webhooks that are created with the configured label and updates the CA Bundle
func (p *Plugin) watchWebhooks(ctx context.Context, c *pluginConfig) (err error) {
	client, err := p.hooks.newKubeClient(c.KubeConfigFilePath)
	if err != nil {
		return err
	}

	_, mutatingWebhookClient, validatingWebhookClient := newKubeClientsets(c, client)
	mutatingWebhookWatcher, validatingWebhookWatcher, err := newWebhookWatchers(ctx, c, mutatingWebhookClient, validatingWebhookClient)
	if err != nil {
		return err
	}

	for {
		select {
		case event := <-mutatingWebhookWatcher.ResultChan():
			if err = p.watchWebhookEvent(ctx, c, mutatingWebhookClient, event); err != nil {
				p.log.Error("handling watch event for mutating webhook", "error", err)
			}
		case event := <-validatingWebhookWatcher.ResultChan():
			if err = p.watchWebhookEvent(ctx, c, validatingWebhookClient, event); err != nil {
				p.log.Error("handling watch event for validating webhook", "error", err)
			}
		case <-p.configUpdated:
			c, err = p.getConfig()
			if err != nil {
				p.log.Error("getting updated config", "error", err)
			}
			stopWebhookWatchers(mutatingWebhookWatcher, validatingWebhookWatcher)
			mutatingWebhookWatcher, validatingWebhookWatcher, err = newWebhookWatchers(ctx, c, mutatingWebhookClient, validatingWebhookClient)
			if err != nil {
				p.log.Error("getting updated webhook watchers", "error", err)
			}
		}
	}

	return nil
}

// watchWebhookEvent triggers the read-modify-write for a newly created webhook
func (p *Plugin) watchWebhookEvent(ctx context.Context, c *pluginConfig, client kubeClientset, event watch.Event) (err error) {
	switch event.Type {
	case watch.Added:
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

func newKubeClient(configPath string) (*kubernetes.Clientset, error) {
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

// kubeClientset encapsulates the Kubenetes API for config maps, validating webhooks, and mutating webhooks
type kubeClientset interface {
	Get(ctx context.Context, namespace, name string) (runtime.Object, error)
	GetList(ctx context.Context, config *pluginConfig) (runtime.Object, error)
	CreatePatch(ctx context.Context, config *pluginConfig, obj runtime.Object, resp *hostservices.FetchX509IdentityResponse) (runtime.Object, error)
	Patch(ctx context.Context, obj runtime.Object, patchBytes []byte) error
	Watch(ctx context.Context, label string) (watch.Interface, error)
}

// newClientsets creates all of the available clientsets
func newKubeClientsets(c *pluginConfig, clientset *kubernetes.Clientset) (configMapClientset, mutatingWebhookClientset, validatingWebhookClientset) {
	return newConfigMapClientset(c, clientset),
		newMutatingWebhookClientset(c, clientset),
		newValidatingWebhookClientset(c, clientset)
}

func newWebhookWatchers(ctx context.Context, c *pluginConfig, mutatingWebhookClient, validatingWebhookClient kubeClientset) (watch.Interface, watch.Interface, error) {
	mutatingWebhookWatcher, err := mutatingWebhookClient.Watch(ctx, c.WebhookLabel)
	if err != nil {
		return nil, nil, err
	}
	validatingWebhookWatcher, err := validatingWebhookClient.Watch(ctx, c.WebhookLabel)
	if err != nil {
		return nil, nil, err
	}

	return mutatingWebhookWatcher, validatingWebhookWatcher, nil
}

func stopWebhookWatchers(mutatingWebhookWatcher, validatingWebhookWatcher watch.Interface) {
	mutatingWebhookWatcher.Stop()
	validatingWebhookWatcher.Stop()
}

// configMapClientset encapsulates the Kubenetes API for updating the CA Bundle in a config map
type configMapClientset struct {
	*kubernetes.Clientset
}

func newConfigMapClientset(c *pluginConfig, clientset *kubernetes.Clientset) configMapClientset {
	return configMapClientset{Clientset: clientset}
}

func (c configMapClientset) Get(ctx context.Context, namespace, configMap string) (runtime.Object, error) {
	return c.CoreV1().ConfigMaps(namespace).Get(ctx, configMap, metav1.GetOptions{})
}

func (c configMapClientset) GetList(ctx context.Context, config *pluginConfig) (runtime.Object, error) {
	return c.CoreV1().ConfigMaps(config.Namespace).List(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("metadata.name", config.ConfigMap).String(),
	})
}

func (c configMapClientset) CreatePatch(ctx context.Context, config *pluginConfig, obj runtime.Object, resp *hostservices.FetchX509IdentityResponse) (runtime.Object, error) {
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

func (c configMapClientset) Patch(ctx context.Context, obj runtime.Object, patchBytes []byte) error {
	configMapMeta, err := meta.Accessor(obj)
	if err != nil {
		return err
	}
	_, err = c.CoreV1().ConfigMaps(configMapMeta.GetNamespace()).Patch(ctx, configMapMeta.GetName(), types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{})
	return err
}

func (c configMapClientset) Watch(ctx context.Context, label string) (watch.Interface, error) {
	return nil, nil
}

// mutatingWebhookClientset encapsulates the Kubenetes API for updating the CA Bundle in a mutating webhook
type mutatingWebhookClientset struct {
	*kubernetes.Clientset
}

func newMutatingWebhookClientset(c *pluginConfig, clientset *kubernetes.Clientset) mutatingWebhookClientset {
	return mutatingWebhookClientset{Clientset: clientset}
}

func (c mutatingWebhookClientset) Get(ctx context.Context, namespace, mutatingWebhook string) (runtime.Object, error) {
	return c.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, mutatingWebhook, metav1.GetOptions{})
}

func (c mutatingWebhookClientset) GetList(ctx context.Context, config *pluginConfig) (runtime.Object, error) {
	return c.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=true", config.WebhookLabel),
	})
}

func (c mutatingWebhookClientset) CreatePatch(ctx context.Context, config *pluginConfig, obj runtime.Object, resp *hostservices.FetchX509IdentityResponse) (runtime.Object, error) {
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

func (c mutatingWebhookClientset) Patch(ctx context.Context, webhook runtime.Object, patchBytes []byte) error {
	webhookMeta, err := meta.Accessor(webhook)
	if err != nil {
		return err
	}
	_, err = c.AdmissionregistrationV1().MutatingWebhookConfigurations().Patch(ctx, webhookMeta.GetName(), types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{})
	return err
}

func (c mutatingWebhookClientset) Watch(ctx context.Context, label string) (watch.Interface, error) {
	return c.AdmissionregistrationV1().MutatingWebhookConfigurations().Watch(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=true", label),
	})
}

// validatingWebhookClientset encapsulates the Kubenetes API for updating the CA Bundle in a validating webhook
type validatingWebhookClientset struct {
	*kubernetes.Clientset
}

func newValidatingWebhookClientset(c *pluginConfig, clientset *kubernetes.Clientset) validatingWebhookClientset {
	return validatingWebhookClientset{Clientset: clientset}
}

func (c validatingWebhookClientset) Get(ctx context.Context, namespace, validatingWebhook string) (runtime.Object, error) {
	return c.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, validatingWebhook, metav1.GetOptions{})
}

func (c validatingWebhookClientset) GetList(ctx context.Context, config *pluginConfig) (runtime.Object, error) {
	return c.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=true", config.WebhookLabel),
	})
}

func (c validatingWebhookClientset) CreatePatch(ctx context.Context, config *pluginConfig, obj runtime.Object, resp *hostservices.FetchX509IdentityResponse) (runtime.Object, error) {
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

func (c validatingWebhookClientset) Patch(ctx context.Context, webhook runtime.Object, patchBytes []byte) error {
	webhookMeta, err := meta.Accessor(webhook)
	if err != nil {
		return err
	}
	_, err = c.AdmissionregistrationV1().ValidatingWebhookConfigurations().Patch(ctx, webhookMeta.GetName(), types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{})
	return err
}

func (c validatingWebhookClientset) Watch(ctx context.Context, label string) (watch.Interface, error) {
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
