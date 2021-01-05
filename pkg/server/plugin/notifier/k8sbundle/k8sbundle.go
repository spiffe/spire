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
	corev1 "k8s.io/api/core/v1"
	admissionv1 "k8s.io/api/admissionregistration/v1"
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

	mu               sync.RWMutex
	log              hclog.Logger
	config           *pluginConfig
	identityProvider hostservices.IdentityProvider

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
		clientset, err := p.hooks.newKubeClient(config.KubeConfigFilePath)
		if err != nil {
			return nil, err
		}

		// ignore the bundle presented in the request. see updateBundle for details on why.
		if err := p.updateBundles(ctx, config, clientset); err != nil {
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
		clientset, err := p.hooks.newKubeClient(config.KubeConfigFilePath)
		if err != nil {
			return nil, err
		}

		// ignore the bundle presented in the request. see updateBundle for details on why.
		if err := p.updateBundles(ctx, config, clientset); err != nil {
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
	go func() {
		err := p.watchWebhooks(ctx, config)
		if err != nil {
			p.log.Error("Error setting up webhook watcher: %v", err)
		}
	} ()
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

func (p *Plugin) updateBundles(ctx context.Context, c *pluginConfig, clientset *kubernetes.Clientset) (err error) {
	clients := newClientsets(c, clientset)

	for _, client := range(clients) {
		list, err := client.GetList(ctx)
		if err != nil {
			return k8sErr.New("unable to get list:", err)
		}
		listItems, err := meta.ExtractList(list)
		if err != nil {
			return k8sErr.New("unable to extract webhook list items with %s label: %v", c.WebhookLabel, err)
		}
		for _, item := range listItems {
			itemMeta, err := meta.Accessor(item)
			if err != nil {
				return err
			}
			if err := p.updateBundle(ctx, c, client, itemMeta.GetNamespace(), itemMeta.GetName()); err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *Plugin) updateBundle(ctx context.Context, c *pluginConfig, client kubeClient, namespace, name string) (err error) {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		webhook, err := client.Get(ctx, namespace, name)
		if err != nil {
			return k8sErr.New("unable to get webhook %s: %v", name, err)
		}

		// Load bundle data from the registration api. The bundle has to be
		// loaded after fetching the validating webhook so we can properly detect and
		// correct a race updating the bundle (i.e.  read-modify-write
		// semantics).
		resp, err := p.identityProvider.FetchX509Identity(ctx, &hostservices.FetchX509IdentityRequest{})
		if err != nil {
			return err
		}

		// Create patch with updated CA Bundles
		patch, err := client.Update(ctx, webhook, resp)
		if err != nil {
			return err
		}

		// Patch the ValidatingWebhookConfiguration
		patchBytes, err := json.Marshal(patch)
		if err != nil {
			return k8sErr.New("unable to marshal patch: %v", err)
		}
		return client.Patch(ctx, webhook, patchBytes)
	})
}

// Watches for new webhooks that are created with the configured label and updates the CA Bundle
func (p *Plugin) watchWebhooks(ctx context.Context, c *pluginConfig) (err error) {
	clientset, err := p.hooks.newKubeClient(c.KubeConfigFilePath)
	if err != nil {
		return err
	}
	validatingWebhookClient := newValidatingWebhookClientset(c, clientset)
	mutatingWebhookClient := newMutatingWebhookClientset(c, clientset)

	validatingWebhookWatcher, err := validatingWebhookClient.Watch(ctx, c.WebhookLabel)
	if err != nil {
		return err
	}
	mutatingWebhookWatcher, err := mutatingWebhookClient.Watch(ctx, c.WebhookLabel)
	if err != nil {
		return err
	}

	for  {
		select {
		case event := <-validatingWebhookWatcher.ResultChan():
			err = p.watchEvent(ctx, c, validatingWebhookClient, event)
			if err != nil {
				p.log.Error("Error received watching validating webhook: %v", err)
			}
		case event := <-mutatingWebhookWatcher.ResultChan():
			err = p.watchEvent(ctx, c, mutatingWebhookClient, event)
			if err != nil {
				p.log.Error("Error received watching mutating webhook: %v", err)
			}
		}
	}

	return nil
}

func (p *Plugin) watchEvent(ctx context.Context, c *pluginConfig, client kubeClient, event watch.Event) (err error) {
	switch event.Type {
	case watch.Added:
		webhookMeta, err := meta.Accessor(event.Object)
		if err != nil {
			return err
		}
		p.updateBundle(ctx, c, client, webhookMeta.GetNamespace(), webhookMeta.GetName())
		if err != nil {
			return err
		}
	}

	return nil
}

// Creates an array of the available clientsets
func newClientsets(c *pluginConfig, clientset *kubernetes.Clientset) []kubeClient {
	clients :=[]kubeClient{newConfigMapClientset(c, clientset)}
	if c.WebhookLabel != "" {
		clients = append(clients,
			newMutatingWebhookClientset(c, clientset),
			newValidatingWebhookClientset(c, clientset),
		)
	}

	return clients
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

type kubeClient interface {
	Get(ctx context.Context, namespace, name string) (runtime.Object, error)
	GetList(ctx context.Context) (runtime.Object, error)
	Patch(ctx context.Context, obj runtime.Object, patchBytes []byte) error
	Update(ctx context.Context, obj runtime.Object, resp *hostservices.FetchX509IdentityResponse) (runtime.Object, error)
	Watch(ctx context.Context, label string) (watch.Interface, error)
}

// Config map
func newConfigMapClientset(c *pluginConfig, clientset *kubernetes.Clientset) configMapClientset {
	return configMapClientset{Clientset: clientset, config: c}
}

type configMapClientset struct {
	*kubernetes.Clientset
	config *pluginConfig
}

func (c configMapClientset) Get(ctx context.Context, namespace, configMap string) (runtime.Object, error) {
	return c.CoreV1().ConfigMaps(namespace).Get(ctx, configMap, metav1.GetOptions{})
}

func (c configMapClientset) GetList(ctx context.Context) (runtime.Object, error) {
	return c.CoreV1().ConfigMaps(c.config.Namespace).List(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("metadata.name", c.config.ConfigMap).String(),
	})
}

func (c configMapClientset) Patch(ctx context.Context, obj runtime.Object, patchBytes []byte) error {
	configMapMeta, err := meta.Accessor(obj)
	if err != nil {
		return err
	}
	_, err = c.CoreV1().ConfigMaps(configMapMeta.GetNamespace()).Patch(ctx, configMapMeta.GetName(), types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{})
	return err
}

func (c configMapClientset) Update(ctx context.Context, obj runtime.Object, resp *hostservices.FetchX509IdentityResponse) (runtime.Object, error) {
	configMap, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return nil, k8sErr.New("wrong type, expecting config map")
	}
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			ResourceVersion: configMap.ResourceVersion,
		},
		Data: map[string]string{
			c.config.ConfigMapKey: bundleData(resp.Bundle),
		},
	}, nil
}

func (c configMapClientset) Watch(ctx context.Context, label string) (watch.Interface, error) {
	return nil, nil
}

// Validating webhook
func newValidatingWebhookClientset(c *pluginConfig, clientset *kubernetes.Clientset) validatingWebhookClientset {
	return validatingWebhookClientset{Clientset: clientset, config: c}
}

type validatingWebhookClientset struct {
	*kubernetes.Clientset
	config *pluginConfig
}

func (c validatingWebhookClientset) Get(ctx context.Context, namespace, validatingWebhook string) (runtime.Object, error) {
	return c.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, validatingWebhook, metav1.GetOptions{})
}

func (c validatingWebhookClientset) GetList(ctx context.Context) (runtime.Object, error) {
	return c.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=true", c.config.WebhookLabel),
	})
}

func (c validatingWebhookClientset) Patch(ctx context.Context, webhook runtime.Object, patchBytes []byte) error {
	webhookMeta, err := meta.Accessor(webhook)
	if err != nil {
		return err
	}
	_, err = c.AdmissionregistrationV1().ValidatingWebhookConfigurations().Patch(ctx, webhookMeta.GetName(), types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{})
	return err
}

func (c validatingWebhookClientset) Update(ctx context.Context, obj runtime.Object, resp *hostservices.FetchX509IdentityResponse) (runtime.Object, error) {
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

func (c validatingWebhookClientset) Watch(ctx context.Context, label string) (watch.Interface, error) {
	return c.AdmissionregistrationV1().ValidatingWebhookConfigurations().Watch(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=true", label),
	})
}

// Mutating webhook
func newMutatingWebhookClientset(c *pluginConfig, clientset *kubernetes.Clientset) mutatingWebhookClientset {
	return mutatingWebhookClientset{Clientset: clientset, config: c}
}

type mutatingWebhookClientset struct {
	*kubernetes.Clientset
	config *pluginConfig
}

func (c mutatingWebhookClientset) Get(ctx context.Context, namespace, mutatingWebhook string) (runtime.Object, error) {
	return c.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, mutatingWebhook, metav1.GetOptions{})
}

func (c mutatingWebhookClientset) GetList(ctx context.Context) (runtime.Object, error) {
	return c.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=true", c.config.WebhookLabel),
	})
}

func (c mutatingWebhookClientset) Patch(ctx context.Context, webhook runtime.Object, patchBytes []byte) error {
	webhookMeta, err := meta.Accessor(webhook)
	if err != nil {
		return err
	}
	_, err = c.AdmissionregistrationV1().MutatingWebhookConfigurations().Patch(ctx, webhookMeta.GetName(), types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{})
	return err
}

func (c mutatingWebhookClientset) Update(ctx context.Context, obj runtime.Object, resp *hostservices.FetchX509IdentityResponse) (runtime.Object, error) {
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

	// Step through all the the webhooks in the ValidatingWebhookConfiguration
	for i := range patch.Webhooks {
		patch.Webhooks[i].AdmissionReviewVersions = mutatingWebhook.Webhooks[i].AdmissionReviewVersions
		patch.Webhooks[i].ClientConfig.CABundle = []byte(bundleData(resp.Bundle))
		patch.Webhooks[i].Name = mutatingWebhook.Webhooks[i].Name
		patch.Webhooks[i].SideEffects = mutatingWebhook.Webhooks[i].SideEffects
	}

	return patch, nil
}

func (c mutatingWebhookClientset) Watch(ctx context.Context, label string) (watch.Interface, error) {
	return c.AdmissionregistrationV1().MutatingWebhookConfigurations().Watch(ctx, metav1.ListOptions{
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
