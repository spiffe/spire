package k8sbundle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	identityproviderv0 "github.com/spiffe/spire/proto/spire/hostservice/server/identityprovider/v0"
	"github.com/spiffe/spire/test/fakes/fakeidentityprovider"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
)

const (
	testTimeout = time.Minute
)

func TestBundleWatcherErrorsWhenCannotCreateClient(t *testing.T) {
	test := setupWatcherTest("")
	raw := test.loadPluginRaw(t, "")

	_, err := newBundleWatcher(context.TODO(), raw, raw.config)
	require.Equal(t, err.Error(), "kube client not configured")
}

func TestBundleWatchersStartsAndStops(t *testing.T) {
	fakeWebhook := newFakeKubeClient()
	test := setupWatcherTest("", fakeWebhook)

	raw := test.loadPluginRaw(t, "")

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error)
	watcherStarted := make(chan struct{})
	watcher, err := newBundleWatcher(ctx, raw, raw.config)
	require.NoError(t, err)

	watcher.hooks.watch = func(ctx context.Context) error {
		watcherStarted <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}
	go func() {
		errCh <- watcher.Watch(ctx)
	}()

	timer := time.NewTimer(testTimeout)
	defer timer.Stop()

	select {
	case <-watcherStarted:
	case err := <-errCh:
		if err != nil {
			require.FailNow(t, fmt.Sprintf("watcher.Watch() unexpected exit: %v", err))
		} else {
			require.FailNow(t, "watcher.Watch() unexpected exit")
		}
	case <-timer.C:
		require.FailNow(t, "timed out waiting for watcher to start")
	}

	cancel()

	select {
	case err := <-errCh:
		require.Equal(t, err.Error(), "context canceled")
	case <-timer.C:
		require.FailNow(t, "timed out waiting for watcher.Watch() to return")
	}
}

func TestBundleWatcherUpdateConfig(t *testing.T) {
	w := newFakeWebhook()
	a := newFakeAPIService()

	test := setupWatcherTest("/some/file/path", w, a)

	raw := test.loadPluginRaw(t, `
webhook_label = "WEBHOOK_LABEL"
api_service_label = "API_SERVICE_LABEL"
kube_config_file_path = "/some/file/path"
`)

	require.NotNil(t, raw.cancelWatcher)
	require.Eventually(t, func() bool {
		return w.getWatchLabel() == "WEBHOOK_LABEL"
	}, testTimeout, time.Second)

	require.Eventually(t, func() bool {
		return a.getWatchLabel() == "API_SERVICE_LABEL"
	}, testTimeout, time.Second)

	_, err := raw.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: `
webhook_label = "WEBHOOK_LABEL2"
api_service_label = "API_SERVICE_LABEL2"
kube_config_file_path = "/some/file/path"
`,
	})
	require.NoError(t, err)

	require.NotNil(t, raw.cancelWatcher)
	require.Eventually(t, func() bool {
		return w.getWatchLabel() == "WEBHOOK_LABEL2"
	}, testTimeout, time.Second)

	require.Eventually(t, func() bool {
		return a.getWatchLabel() == "API_SERVICE_LABEL2"
	}, testTimeout, time.Second)
}

func TestBundleWatcherAddWebhookEvent(t *testing.T) {
	w := newFakeWebhook()
	test := setupWatcherTest("/some/file/path", w)

	raw := test.loadPluginRaw(t, `
webhook_label = "WEBHOOK_LABEL"
kube_config_file_path = "/some/file/path"
`)

	require.NotNil(t, raw.cancelWatcher)

	webhook := newWebhook()
	test.identityProvider.AppendBundle(testBundle)
	w.setWebhook(webhook)
	w.addWatchEvent(webhook)

	require.Eventually(t, func() bool {
		return assert.Equal(t, &admissionv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:            webhook.Name,
				ResourceVersion: "2",
			},
			Webhooks: []admissionv1.MutatingWebhook{
				{
					ClientConfig: admissionv1.WebhookClientConfig{
						CABundle: []byte(testBundleData),
					},
				},
			},
		}, w.getWebhook(webhook.Name))
	}, testTimeout, time.Second)
}

func TestBundleWatcherAddAPIServiceEvent(t *testing.T) {
	a := newFakeAPIService()
	test := setupWatcherTest("/some/file/path", a)
	raw := test.loadPluginRaw(t, `
api_service_label = "API_SERVICE_LABEL"
kube_config_file_path = "/some/file/path"
`)

	require.NotNil(t, raw.cancelWatcher)
	test.identityProvider.AppendBundle(testBundle)

	apiService := newAPIService()
	a.setAPIService(apiService)
	a.addWatchEvent(apiService)
	require.Eventually(t, func() bool {
		return assert.Equal(t, &apiregistrationv1.APIService{
			ObjectMeta: metav1.ObjectMeta{
				Name:            apiService.Name,
				ResourceVersion: "2",
			},
			Spec: apiregistrationv1.APIServiceSpec{
				CABundle: []byte(testBundleData),
			},
		}, a.getAPIService(apiService.Name))
	}, testTimeout, time.Second)
}

type fakeWebhook struct {
	mu         sync.RWMutex
	fakeWatch  *watch.FakeWatcher
	webhooks   map[string]*admissionv1.MutatingWebhookConfiguration
	watchLabel string
}

func newFakeWebhook() *fakeWebhook {
	w := &fakeWebhook{
		fakeWatch: watch.NewFake(),
		webhooks:  make(map[string]*admissionv1.MutatingWebhookConfiguration),
	}
	return w
}

func (w *fakeWebhook) Get(ctx context.Context, namespace, name string) (runtime.Object, error) {
	entry := w.getWebhook(name)
	if entry == nil {
		return nil, errors.New("not found")
	}
	return entry, nil
}

func (w *fakeWebhook) GetList(ctx context.Context, config *pluginConfig) (runtime.Object, error) {
	list := w.getWebhookList()
	if list.Items == nil {
		return nil, errors.New("not found")
	}
	return list, nil
}

func (w *fakeWebhook) CreatePatch(ctx context.Context, config *pluginConfig, obj runtime.Object, resp *identityproviderv0.FetchX509IdentityResponse) (runtime.Object, error) {
	webhook, ok := obj.(*admissionv1.MutatingWebhookConfiguration)
	if !ok {
		return nil, status.Error(codes.Internal, "wrong type, expecting mutating webhook")
	}
	return &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			ResourceVersion: webhook.ResourceVersion,
		},
		Webhooks: []admissionv1.MutatingWebhook{
			{
				ClientConfig: admissionv1.WebhookClientConfig{
					CABundle: []byte(bundleData(resp.Bundle)),
				},
			},
		},
	}, nil
}

func (w *fakeWebhook) Patch(ctx context.Context, namespace, name string, patchBytes []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	entry, ok := w.webhooks[name]
	if !ok {
		return errors.New("not found")
	}

	patchedWebhook := new(admissionv1.MutatingWebhookConfiguration)
	if err := json.Unmarshal(patchBytes, patchedWebhook); err != nil {
		return err
	}
	resourceVersion, err := strconv.Atoi(patchedWebhook.ResourceVersion)
	if err != nil {
		return errors.New("patch does not have resource version")
	}
	entry.ResourceVersion = fmt.Sprint(resourceVersion + 1)
	for i := range entry.Webhooks {
		entry.Webhooks[i].ClientConfig.CABundle = patchedWebhook.Webhooks[i].ClientConfig.CABundle
	}
	return nil
}

func (w *fakeWebhook) Watch(ctx context.Context, config *pluginConfig) (watch.Interface, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.watchLabel = config.WebhookLabel
	return w.fakeWatch, nil
}

func (w *fakeWebhook) getWebhook(name string) *admissionv1.MutatingWebhookConfiguration {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.webhooks[name]
}

func (w *fakeWebhook) getWebhookList() *admissionv1.MutatingWebhookConfigurationList {
	w.mu.RLock()
	defer w.mu.RUnlock()
	webhookList := &admissionv1.MutatingWebhookConfigurationList{}
	for _, webhook := range w.webhooks {
		webhookList.Items = append(webhookList.Items, *webhook)
	}
	return webhookList
}

func (w *fakeWebhook) setWebhook(webhook *admissionv1.MutatingWebhookConfiguration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.webhooks[webhook.Name] = webhook
}

func (w *fakeWebhook) addWatchEvent(obj runtime.Object) {
	w.fakeWatch.Add(obj)
}

func (w *fakeWebhook) getWatchLabel() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.watchLabel
}

func newWebhook() *admissionv1.MutatingWebhookConfiguration {
	return &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "spire-webhook",
			ResourceVersion: "1",
		},
		Webhooks: []admissionv1.MutatingWebhook{
			{
				ClientConfig: admissionv1.WebhookClientConfig{},
			},
		},
	}
}

type fakeAPIService struct {
	mu          sync.RWMutex
	fakeWatch   *watch.FakeWatcher
	apiServices map[string]*apiregistrationv1.APIService
	watchLabel  string
}

func newFakeAPIService() *fakeAPIService {
	return &fakeAPIService{
		fakeWatch:   watch.NewFake(),
		apiServices: make(map[string]*apiregistrationv1.APIService),
	}
}

func (a *fakeAPIService) Get(ctx context.Context, namespace, name string) (runtime.Object, error) {
	entry := a.getAPIService(name)
	if entry == nil {
		return nil, errors.New("not found")
	}
	return entry, nil
}

func (a *fakeAPIService) GetList(ctx context.Context, config *pluginConfig) (runtime.Object, error) {
	list := a.getAPIServiceList()
	if list.Items == nil {
		return nil, errors.New("not found")
	}
	return list, nil
}

func (a *fakeAPIService) CreatePatch(ctx context.Context, config *pluginConfig, obj runtime.Object, resp *identityproviderv0.FetchX509IdentityResponse) (runtime.Object, error) {
	webhook, ok := obj.(*apiregistrationv1.APIService)
	if !ok {
		return nil, status.Error(codes.Internal, "wrong type, expecting API service")
	}
	return &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			ResourceVersion: webhook.ResourceVersion,
		},
		Spec: apiregistrationv1.APIServiceSpec{
			CABundle: []byte(bundleData(resp.Bundle)),
		},
	}, nil
}

func (a *fakeAPIService) Patch(ctx context.Context, namespace, name string, patchBytes []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	entry, ok := a.apiServices[name]
	if !ok {
		return errors.New("not found")
	}

	patchedAPIService := new(apiregistrationv1.APIService)
	if err := json.Unmarshal(patchBytes, patchedAPIService); err != nil {
		return err
	}
	resourceVersion, err := strconv.Atoi(patchedAPIService.ResourceVersion)
	if err != nil {
		return errors.New("patch does not have resource version")
	}
	entry.ResourceVersion = fmt.Sprint(resourceVersion + 1)
	entry.Spec.CABundle = patchedAPIService.Spec.CABundle
	return nil
}

func (a *fakeAPIService) Watch(ctx context.Context, config *pluginConfig) (watch.Interface, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.watchLabel = config.APIServiceLabel
	return a.fakeWatch, nil
}

func (a *fakeAPIService) getAPIService(name string) *apiregistrationv1.APIService {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.apiServices[name]
}

func (a *fakeAPIService) getAPIServiceList() *apiregistrationv1.APIServiceList {
	a.mu.RLock()
	defer a.mu.RUnlock()
	apiServiceList := &apiregistrationv1.APIServiceList{}
	for _, apiService := range a.apiServices {
		apiServiceList.Items = append(apiServiceList.Items, *apiService)
	}
	return apiServiceList
}

func (a *fakeAPIService) setAPIService(apiService *apiregistrationv1.APIService) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.apiServices[apiService.Name] = apiService
}

func (a *fakeAPIService) addWatchEvent(obj runtime.Object) {
	a.fakeWatch.Add(obj)
}

func (a *fakeAPIService) getWatchLabel() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.watchLabel
}

func newAPIService() *apiregistrationv1.APIService {
	return &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "spire-api-service",
			ResourceVersion: "1",
		},
		Spec: apiregistrationv1.APIServiceSpec{},
	}
}

func setupWatcherTest(expectPath string, clients ...kubeClient) *watcherTest {
	return &watcherTest{
		identityProvider: fakeidentityprovider.New(),
		clients:          clients,
		expectPath:       expectPath,
	}
}

type watcherTest struct {
	clients          []kubeClient
	expectPath       string
	identityProvider *fakeidentityprovider.IdentityProvider
}

func (w *watcherTest) loadPluginRaw(t *testing.T, configuration string) *Plugin {
	notifier := new(notifier.V1)
	raw := New()
	raw.hooks.newKubeClient = func(c *pluginConfig) ([]kubeClient, error) {
		require.Equal(t, w.expectPath, c.KubeConfigFilePath)
		if len(w.clients) == 0 {
			return nil, errors.New("kube client not configured")
		}
		return w.clients, nil
	}

	plugintest.Load(t, builtIn(raw), notifier,
		plugintest.HostServices(identityproviderv0.IdentityProviderServiceServer(w.identityProvider)),
		plugintest.Configure(configuration),
	)

	return raw
}
