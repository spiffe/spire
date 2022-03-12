package k8sbundle

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	identityproviderv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/identityprovider/v1"
	notifierv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/notifier/v1"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	aggregator "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	aggregatorinformers "k8s.io/kube-aggregator/pkg/client/informers/externalversions"
)

const (
	defaultNamespace    = "spire"
	defaultConfigMap    = "spire-bundle"
	defaultConfigMapKey = "bundle.crt"
)

func BuiltIn() catalog.BuiltIn {
	return builtIn(New())
}

func builtIn(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn("k8sbundle",
		notifierv1.NotifierPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type cluster struct {
	Namespace          string `hcl:"namespace"`
	ConfigMap          string `hcl:"config_map"`
	ConfigMapKey       string `hcl:"config_map_key"`
	WebhookLabel       string `hcl:"webhook_label"`
	APIServiceLabel    string `hcl:"api_service_label"`
	KubeConfigFilePath string `hcl:"kube_config_file_path"`
}

type pluginConfig struct {
	cluster  `hcl:",squash"` // for hcl v2 it should be `hcl:",remain"`
	Clusters []cluster       `hcl:"clusters"`
}

type Plugin struct {
	notifierv1.UnsafeNotifierServer
	configv1.UnsafeConfigServer

	mu               sync.RWMutex
	log              hclog.Logger
	config           *pluginConfig
	identityProvider identityproviderv1.IdentityProviderServiceClient
	clients          []kubeClient
	stopCh           chan struct{}

	hooks struct {
		newKubeClients func(c *pluginConfig) ([]kubeClient, error)
	}
}

func New() *Plugin {
	p := &Plugin{}
	p.hooks.newKubeClients = p.newKubeClients
	return p
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) BrokerHostServices(broker pluginsdk.ServiceBroker) error {
	if !broker.BrokerClient(&p.identityProvider) {
		return status.Errorf(codes.FailedPrecondition, "IdentityProvider host service is required")
	}
	return nil
}

func (p *Plugin) Notify(ctx context.Context, req *notifierv1.NotifyRequest) (*notifierv1.NotifyResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	if _, ok := req.Event.(*notifierv1.NotifyRequest_BundleUpdated); ok {
		// ignore the bundle presented in the request. see updateBundle for details on why.
		if err := p.updateBundles(ctx, config); err != nil {
			return nil, err
		}
	}
	return &notifierv1.NotifyResponse{}, nil
}

func (p *Plugin) NotifyAndAdvise(ctx context.Context, req *notifierv1.NotifyAndAdviseRequest) (*notifierv1.NotifyAndAdviseResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	if _, ok := req.Event.(*notifierv1.NotifyAndAdviseRequest_BundleLoaded); ok {
		// ignore the bundle presented in the request. see updateBundle for details on why.
		if err := p.updateBundles(ctx, config); err != nil {
			return nil, err
		}
	}
	return &notifierv1.NotifyAndAdviseResponse{}, nil
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (resp *configv1.ConfigureResponse, err error) {
	config := new(pluginConfig)
	if err := hcl.Decode(&config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	// root set with at least one value or the whole configuration is empty
	if hasRootCluster(&config.cluster) || !hasRootCluster(&config.cluster) && !hasMultipleClusters(config.Clusters) {
		setDefaultValues(&config.cluster)
	}
	for i := range config.Clusters {
		if config.Clusters[i].KubeConfigFilePath == "" {
			return nil, status.Error(codes.InvalidArgument, "cluster configuration is missing kube_config_file_path")
		}
		setDefaultValues(&config.Clusters[i])
	}
	p.setConfig(config)

	clients, err := p.hooks.newKubeClients(config)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to create new kubeClients: %v", err)
	}
	p.setClients(clients)

	p.startInformers(config, clients)

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) getConfig() (*pluginConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func (p *Plugin) setConfig(config *pluginConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.config = config
}

func (p *Plugin) getClients() ([]kubeClient, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.clients == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.clients, nil
}

func (p *Plugin) setClients(clients []kubeClient) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.clients = clients
}

// startInformers creates informers to set CA Bundle in objects created after server has started
func (p *Plugin) startInformers(config *pluginConfig, clients []kubeClient) {
	p.mu.Lock()
	defer p.mu.Unlock()

	stopCh := make(chan struct{})
	if config.WebhookLabel != "" || config.APIServiceLabel != "" {
		for _, client := range clients {
			informer := client.Informer()
			if informer != nil {
				go informer.Run(stopCh)
			}
		}
	}
	if p.stopCh != nil {
		close(p.stopCh)
		p.stopCh = nil
	}
	if config.WebhookLabel != "" || config.APIServiceLabel != "" {
		p.stopCh = stopCh
	}
}

// updateBundles iterates through all the objects that need an updated CA bundle
// If an error is an encountered updating the bundle for an object, we record the
// error and continue on to the next object
func (p *Plugin) updateBundles(ctx context.Context, c *pluginConfig) (err error) {
	clients, err := p.getClients()
	if err != nil {
		return err
	}

	var updateErrs string
	for _, client := range clients {
		list, err := client.GetList(ctx)
		if err != nil {
			updateErrs += fmt.Sprintf("unable to get list: %v, ", err)
			continue
		}
		listItems, err := meta.ExtractList(list)
		if err != nil {
			updateErrs += fmt.Sprintf("unable to extract list items: %v, ", err)
			continue
		}
		for _, item := range listItems {
			itemMeta, err := meta.Accessor(item)
			if err != nil {
				updateErrs += fmt.Sprintf("unable to extract metadata for item: %v, ", err)
				continue
			}
			err = p.updateBundle(ctx, client, itemMeta.GetNamespace(), itemMeta.GetName())
			if err != nil && status.Code(err) != codes.AlreadyExists {
				updateErrs += fmt.Sprintf("%s: %v, ", namespacedName(itemMeta), err)
			}
		}
	}

	if len(updateErrs) > 0 {
		return status.Errorf(codes.Internal, "unable to update: %s", strings.TrimSuffix(updateErrs, ", "))
	}
	return nil
}

// updateBundle does the ready-modify-write semantics for Kubernetes, retrying on conflict
func (p *Plugin) updateBundle(ctx context.Context, client kubeClient, namespace, name string) (err error) {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// Get the object so we can use the version to resolve conflicts racing
		// on updates from other servers.
		obj, err := client.Get(ctx, namespace, name)
		if err != nil {
			return status.Errorf(codes.Internal, "unable to get object %s/%s: %v", namespace, name, err)
		}

		// Load bundle data from the IdentityProvider host service. The bundle
		// has to be loaded after fetching the object so we can properly detect
		// and correct a race updating the bundle (i.e.  read-modify-write
		// semantics).
		resp, err := p.identityProvider.FetchX509Identity(ctx, &identityproviderv1.FetchX509IdentityRequest{})
		if err != nil {
			return err
		}

		// Build patch with the new bundle data. The resource version MUST be set
		// to support conflict resolution.
		patch, err := client.CreatePatch(ctx, obj, resp)
		if err != nil {
			return err
		}

		// Patch the bundle, handling version conflicts
		patchBytes, err := json.Marshal(patch)
		if err != nil {
			return status.Errorf(codes.Internal, "unable to marshal patch: %v", err)
		}
		return client.Patch(ctx, namespace, name, patchBytes)
	})
}

// informerEvent triggers the read-modify-write for a newly created object
func (p *Plugin) informerEvent(client kubeClient, obj runtime.Object) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	objectMeta, err := meta.Accessor(obj)
	if err != nil {
		return err
	}

	err = p.updateBundle(ctx, client, objectMeta.GetNamespace(), objectMeta.GetName())
	switch {
	case err == nil:
		p.log.Debug("Set bundle for object", "name", objectMeta.GetName())
	case status.Code(err) == codes.FailedPrecondition:
		// Ignore FailPrecondition errors for when SPIRE is booting and we receive an event prior to
		// IdentityProvider being initialized. In this case the BundleLoaded event will come
		// to populate the caBundle, so its safe to ignore this error.
	case status.Code(err) == codes.AlreadyExists:
		// Updating the bundle from an ADD event triggers a subsequent MODIFIED event. updateBundle will
		// return AlreadyExists since nothing needs to be updated.
	default:
		return err
	}

	return nil
}

func (p *Plugin) newKubeClients(c *pluginConfig) ([]kubeClient, error) {
	clients := []kubeClient{}

	if hasRootCluster(&c.cluster) {
		clusterClients, err := p.newClientsForCluster(c.cluster)
		if err != nil {
			return nil, err
		}
		clients = append(clients, clusterClients...)
	}

	for _, cluster := range c.Clusters {
		clusterClients, err := p.newClientsForCluster(cluster)
		if err != nil {
			return nil, err
		}
		clients = append(clients, clusterClients...)
	}

	return clients, nil
}

func (p *Plugin) newClientsForCluster(c cluster) ([]kubeClient, error) {
	clientset, err := newKubeClientset(c.KubeConfigFilePath)
	if err != nil {
		return nil, err
	}
	aggregatorClientset, err := newAggregatorClientset(c.KubeConfigFilePath)
	if err != nil {
		return nil, err
	}

	clients := []kubeClient{configMapClient{
		Clientset:    clientset,
		namespace:    c.Namespace,
		configMap:    c.ConfigMap,
		configMapKey: c.ConfigMapKey,
	}}
	if c.WebhookLabel != "" {
		factory := informers.NewSharedInformerFactoryWithOptions(
			clientset,
			time.Minute,
			informers.WithTweakListOptions(func(options *metav1.ListOptions) {
				options.LabelSelector = fmt.Sprintf("%s=true", c.WebhookLabel)
			}),
		)
		clients = append(clients,
			mutatingWebhookClient{
				Clientset:    clientset,
				webhookLabel: c.WebhookLabel,
				factory:      factory,
				p:            p,
			},
			validatingWebhookClient{
				Clientset:    clientset,
				webhookLabel: c.WebhookLabel,
				factory:      factory,
				p:            p,
			},
		)
	}
	if c.APIServiceLabel != "" {
		factory := aggregatorinformers.NewSharedInformerFactoryWithOptions(
			aggregatorClientset,
			time.Minute,
			aggregatorinformers.WithTweakListOptions(func(options *metav1.ListOptions) {
				options.LabelSelector = fmt.Sprintf("%s=true", c.APIServiceLabel)
			}),
		)
		clients = append(clients,
			apiServiceClient{
				Clientset:       aggregatorClientset,
				apiServiceLabel: c.APIServiceLabel,
				factory:         factory,
				p:               p,
			},
		)
	}

	return clients, nil
}

func newKubeClientset(configPath string) (*kubernetes.Clientset, error) {
	config, err := getKubeConfig(configPath)
	if err != nil {
		return nil, err
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func newAggregatorClientset(configPath string) (*aggregator.Clientset, error) {
	config, err := getKubeConfig(configPath)
	if err != nil {
		return nil, err
	}

	client, err := aggregator.NewForConfig(config)
	if err != nil {
		return nil, err
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
	GetList(ctx context.Context) (runtime.Object, error)
	CreatePatch(ctx context.Context, obj runtime.Object, resp *identityproviderv1.FetchX509IdentityResponse) (runtime.Object, error)
	Patch(ctx context.Context, namespace, name string, patchBytes []byte) error
	Informer() cache.SharedIndexInformer
}

// configMapClient encapsulates the Kubenetes API for updating the CA Bundle in a config map
type configMapClient struct {
	*kubernetes.Clientset
	namespace    string
	configMap    string
	configMapKey string
}

func (c configMapClient) Get(ctx context.Context, namespace, configMap string) (runtime.Object, error) {
	return c.CoreV1().ConfigMaps(namespace).Get(ctx, configMap, metav1.GetOptions{})
}

func (c configMapClient) GetList(ctx context.Context) (runtime.Object, error) {
	obj, err := c.Get(ctx, c.namespace, c.configMap)
	if err != nil {
		return nil, err
	}
	configMap := obj.(*corev1.ConfigMap)
	return &corev1.ConfigMapList{
		Items: []corev1.ConfigMap{*configMap},
	}, nil
}

func (c configMapClient) CreatePatch(ctx context.Context, obj runtime.Object, resp *identityproviderv1.FetchX509IdentityResponse) (runtime.Object, error) {
	configMap, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "wrong type, expecting ConfigMap")
	}
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			ResourceVersion: configMap.ResourceVersion,
		},
		Data: map[string]string{
			c.configMapKey: bundleData(resp.Bundle),
		},
	}, nil
}

func (c configMapClient) Patch(ctx context.Context, namespace, name string, patchBytes []byte) error {
	_, err := c.CoreV1().ConfigMaps(namespace).Patch(ctx, name, types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{})
	return err
}

func (c configMapClient) Informer() cache.SharedIndexInformer {
	return nil
}

// apiServiceClient encapsulates the Kubenetes API for updating the CA Bundle in an API Service
type apiServiceClient struct {
	*aggregator.Clientset
	apiServiceLabel string
	factory         aggregatorinformers.SharedInformerFactory
	p               *Plugin
}

func (c apiServiceClient) Get(ctx context.Context, namespace, name string) (runtime.Object, error) {
	return c.ApiregistrationV1().APIServices().Get(ctx, name, metav1.GetOptions{})
}

func (c apiServiceClient) GetList(ctx context.Context) (runtime.Object, error) {
	return c.ApiregistrationV1().APIServices().List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=true", c.apiServiceLabel),
	})
}

func (c apiServiceClient) CreatePatch(ctx context.Context, obj runtime.Object, resp *identityproviderv1.FetchX509IdentityResponse) (runtime.Object, error) {
	apiService, ok := obj.(*apiregistrationv1.APIService)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "wrong type, expecting APIService")
	}

	// Check if APIService needs an update
	if bytes.Equal(apiService.Spec.CABundle, []byte(bundleData(resp.Bundle))) {
		return nil, status.Errorf(codes.AlreadyExists, "APIService %s is already up to date", apiService.Name)
	}

	patch := &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			ResourceVersion: apiService.ResourceVersion,
		},
		Spec: apiregistrationv1.APIServiceSpec{
			CABundle:             []byte(bundleData(resp.Bundle)),
			GroupPriorityMinimum: apiService.Spec.GroupPriorityMinimum,
			VersionPriority:      apiService.Spec.VersionPriority,
		},
	}

	return patch, nil
}

func (c apiServiceClient) Patch(ctx context.Context, namespace, name string, patchBytes []byte) error {
	_, err := c.ApiregistrationV1().APIServices().Patch(ctx, name, types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{})
	return err
}

func (c apiServiceClient) Informer() cache.SharedIndexInformer {
	informer := c.factory.Apiregistration().V1().APIServices().Informer()
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onAdd,
		UpdateFunc: c.onUpdate,
	})
	return informer
}

func (c apiServiceClient) onAdd(obj interface{}) {
	if err := c.p.informerEvent(c, obj.(runtime.Object)); err != nil {
		c.p.log.Error("Unable to add bundle to APIService", "error", err)
	}
}

func (c apiServiceClient) onUpdate(oldObj, newObj interface{}) {
	if err := c.p.informerEvent(c, newObj.(runtime.Object)); err != nil {
		c.p.log.Error("Unable to update bundle in APIService", "error", err)
	}
}

// mutatingWebhookClient encapsulates the Kubenetes API for updating the CA Bundle in a mutating webhook
type mutatingWebhookClient struct {
	*kubernetes.Clientset
	webhookLabel string
	factory      informers.SharedInformerFactory
	p            *Plugin
}

func (c mutatingWebhookClient) Get(ctx context.Context, namespace, mutatingWebhook string) (runtime.Object, error) {
	return c.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, mutatingWebhook, metav1.GetOptions{})
}

func (c mutatingWebhookClient) GetList(ctx context.Context) (runtime.Object, error) {
	return c.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=true", c.webhookLabel),
	})
}

func (c mutatingWebhookClient) CreatePatch(ctx context.Context, obj runtime.Object, resp *identityproviderv1.FetchX509IdentityResponse) (runtime.Object, error) {
	mutatingWebhook, ok := obj.(*admissionv1.MutatingWebhookConfiguration)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "wrong type, expecting MutatingWebhookConfiguration")
	}

	// Check if MutatingWebhookConfiguration needs an update
	needsUpdate := false
	for _, webhook := range mutatingWebhook.Webhooks {
		if !bytes.Equal(webhook.ClientConfig.CABundle, []byte(bundleData(resp.Bundle))) {
			needsUpdate = true
			break
		}
	}
	if !needsUpdate {
		return nil, status.Errorf(codes.AlreadyExists, "MutatingWebhookConfiguration %s is already up to date", mutatingWebhook.Name)
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

func (c mutatingWebhookClient) Informer() cache.SharedIndexInformer {
	informer := c.factory.Admissionregistration().V1().MutatingWebhookConfigurations().Informer()
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onAdd,
		UpdateFunc: c.onUpdate,
	})
	return informer
}

func (c mutatingWebhookClient) onAdd(obj interface{}) {
	if err := c.p.informerEvent(c, obj.(runtime.Object)); err != nil {
		c.p.log.Error("Unable to add bundle to MutatingWebhookConfiguration", "error", err)
	}
}

func (c mutatingWebhookClient) onUpdate(oldObj, newObj interface{}) {
	if err := c.p.informerEvent(c, newObj.(runtime.Object)); err != nil {
		c.p.log.Error("Unable to update bundle in MutatingWebhookConfiguration", "error", err)
	}
}

// validatingWebhookClient encapsulates the Kubenetes API for updating the CA Bundle in a validating webhook
type validatingWebhookClient struct {
	*kubernetes.Clientset
	webhookLabel string
	factory      informers.SharedInformerFactory
	p            *Plugin
}

func (c validatingWebhookClient) Get(ctx context.Context, namespace, validatingWebhook string) (runtime.Object, error) {
	return c.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, validatingWebhook, metav1.GetOptions{})
}

func (c validatingWebhookClient) GetList(ctx context.Context) (runtime.Object, error) {
	return c.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=true", c.webhookLabel),
	})
}

func (c validatingWebhookClient) CreatePatch(ctx context.Context, obj runtime.Object, resp *identityproviderv1.FetchX509IdentityResponse) (runtime.Object, error) {
	validatingWebhook, ok := obj.(*admissionv1.ValidatingWebhookConfiguration)
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "wrong type, expecting ValidatingWebhookConfiguration")
	}

	// Check if ValidatingWebhookConfiguration needs an update
	needsUpdate := false
	for _, webhook := range validatingWebhook.Webhooks {
		if !bytes.Equal(webhook.ClientConfig.CABundle, []byte(bundleData(resp.Bundle))) {
			needsUpdate = true
			break
		}
	}
	if !needsUpdate {
		return nil, status.Errorf(codes.AlreadyExists, "ValidatingWebhookConfiguration %s is already up to date", validatingWebhook.Name)
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

func (c validatingWebhookClient) Informer() cache.SharedIndexInformer {
	informer := c.factory.Admissionregistration().V1().ValidatingWebhookConfigurations().Informer()
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onAdd,
		UpdateFunc: c.onUpdate,
	})
	return informer
}

func (c validatingWebhookClient) onAdd(obj interface{}) {
	if err := c.p.informerEvent(c, obj.(runtime.Object)); err != nil {
		c.p.log.Error("Unable to add bundle to ValidatingWebhookConfiguration", "error", err)
	}
}

func (c validatingWebhookClient) onUpdate(oldObj, newObj interface{}) {
	if err := c.p.informerEvent(c, newObj.(runtime.Object)); err != nil {
		c.p.log.Error("Unable to update bundle in ValidatingWebhookConfiguration", "error", err)
	}
}

// bundleData formats the bundle data for inclusion in the config map
func bundleData(bundle *plugintypes.Bundle) string {
	bundleData := new(bytes.Buffer)
	for _, x509Authority := range bundle.X509Authorities {
		_ = pem.Encode(bundleData, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: x509Authority.Asn1,
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

func setDefaultValues(c *cluster) {
	if c.Namespace == "" {
		c.Namespace = defaultNamespace
	}
	if c.ConfigMap == "" {
		c.ConfigMap = defaultConfigMap
	}
	if c.ConfigMapKey == "" {
		c.ConfigMapKey = defaultConfigMapKey
	}
}

func hasRootCluster(config *cluster) bool {
	return *config != cluster{}
}

func hasMultipleClusters(clusters []cluster) bool {
	return len(clusters) > 0
}
